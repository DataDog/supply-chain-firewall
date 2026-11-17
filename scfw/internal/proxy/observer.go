// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	observationPrefixLimit = 64 << 10
	observationHashLimit   = 8 << 20
)

// Observer passively records existing work. Callbacks cannot reject traffic.
// Metadata receives only a bounded candidate, never an enforcement temporary file.
// The caller owns ecosystem classification, decoding, sanitization and persistence.
type Observer struct {
	Record   func(kind, message string, fields map[string]any)
	Metadata func(Request, http.Header, []byte, bool) map[string]any
	slots    chan struct{}
}

// NewObserver shares a bounded candidate budget across all invocation clients.
func NewObserver(record func(string, string, map[string]any), metadata func(Request, http.Header, []byte, bool) map[string]any) *Observer {
	return &Observer{Record: record, Metadata: metadata, slots: make(chan struct{}, 32)}
}

func (o *Observer) notify(kind, message string, fields map[string]any) {
	if o == nil || o.Record == nil {
		return
	}
	// Diagnostics must not turn a callback failure into an installation failure.
	defer func() { _ = recover() }()
	o.Record(kind, message, fields)
}

func observedHeaders(headers http.Header) map[string]any {
	result := make(map[string]any)
	for _, key := range []string{"Accept", "Content-Type", "Content-Length", "Content-Encoding", "Location", "ETag", "Last-Modified", "Range", "Content-Range"} {
		if value := headers.Get(key); value != "" {
			result[key] = value
		}
	}
	return result
}

// ObserveTransport wraps an existing transport without changing routes or TLS.
// CloseIdleConnections continues to reach the underlying transport.
func ObserveTransport(base http.RoundTripper, observer *Observer, client string) http.RoundTripper {
	if observer == nil {
		return base
	}
	return &observedTransport{base: base, observer: observer, client: client}
}

type observedTransport struct {
	base     http.RoundTripper
	observer *Observer
	client   string
}

func (t *observedTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *observedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	start := time.Now()
	t.observer.notify("http.forward", "Forwarding an HTTP request", map[string]any{"client": t.client, "method": request.Method, "url": request.URL.String(), "headers": observedHeaders(request.Header), "advertised_request_bytes": request.ContentLength})
	response, err := t.base.RoundTrip(request)
	if err != nil {
		t.observer.notify("http.error", "HTTP transport failed", map[string]any{"client": t.client, "url": request.URL.String(), "error": err, "elapsed_ns": int64(time.Since(start))})
		return response, err
	}
	t.observer.notify("http.response", "Received HTTP response headers", map[string]any{"client": t.client, "url": request.URL.String(), "status": response.StatusCode, "headers": observedHeaders(response.Header), "advertised_response_bytes": response.ContentLength, "elapsed_ns": int64(time.Since(start))})
	if response.Body == nil || response.StatusCode == http.StatusSwitchingProtocols {
		return response, nil
	}
	body := &observedBody{ReadCloser: response.Body, observer: t.observer, request: Request{Method: request.Method, URL: *request.URL, ClientIdentity: t.client}, header: response.Header.Clone(), start: start, client: t.client, expected: response.ContentLength, complete: response.Body == http.NoBody || response.ContentLength == 0, digest: sha256.New()}
	if response.Body == http.NoBody {
		// HEAD may advertise the representation's length despite having no body.
		body.expected = 0
	}
	if t.observer.Metadata != nil {
		select {
		case t.observer.slots <- struct{}{}:
			body.candidate = true
		default:
		}
	}
	response.Body = body
	return response, nil
}

type observedBody struct {
	io.ReadCloser
	observer                                           *Observer
	request                                            Request
	header                                             http.Header
	start                                              time.Time
	client                                             string
	mu                                                 sync.Mutex
	digest                                             hash.Hash
	prefix                                             []byte
	read, hashed, expected                             int64
	active                                             int
	complete, closing, emitted, candidate, readFailure bool
}

func (b *observedBody) Read(buffer []byte) (int, error) {
	b.mu.Lock()
	b.active++
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(buffer)
	b.mu.Lock()
	b.active--
	if !b.emitted {
		b.read += int64(n)
		if b.hashed < observationHashLimit {
			count := min(n, int(observationHashLimit-b.hashed))
			_, _ = b.digest.Write(buffer[:count])
			b.hashed += int64(count)
		}
		if b.candidate && len(b.prefix) < observationPrefixLimit {
			b.prefix = append(b.prefix, buffer[:min(n, observationPrefixLimit-len(b.prefix))]...)
		}
		b.complete = (errors.Is(err, io.EOF) && (b.expected < 0 || b.read == b.expected)) || (err == nil && b.expected >= 0 && b.read == b.expected)
		b.readFailure = b.readFailure || (err != nil && !errors.Is(err, io.EOF))
	}
	b.mu.Unlock()
	b.finish()
	return n, err
}

func (b *observedBody) Close() error {
	err := b.ReadCloser.Close()
	b.mu.Lock()
	b.closing = true
	b.mu.Unlock()
	b.finish()
	return err
}

func (b *observedBody) finish() {
	b.mu.Lock()
	if b.emitted || b.active != 0 || (!b.complete && !b.closing && !b.readFailure) {
		b.mu.Unlock()
		return
	}
	b.emitted = true
	fields := map[string]any{"client": b.client, "url": b.request.URL.String(), "observed_upstream_bytes": b.read, "bytes_hashed": b.hashed, "sha256": hex.EncodeToString(b.digest.Sum(nil)), "digest_complete": b.complete && b.read == b.hashed, "body_complete": b.complete, "read_failed": b.readFailure, "elapsed_ns": int64(time.Since(b.start))}
	prefix := b.prefix
	complete := b.complete && int64(len(prefix)) == b.read
	b.prefix = nil
	candidate := b.candidate
	b.mu.Unlock()
	if candidate {
		defer func() { <-b.observer.slots }()
		fields["body"] = b.metadata(prefix, complete)
	} else {
		fields["body"] = map[string]any{"omitted": "candidate concurrency budget or metadata disabled"}
	}
	b.observer.notify("http.body", "Finished observing an upstream response body", fields)
}

func (b *observedBody) metadata(prefix []byte, complete bool) (result map[string]any) {
	defer func() {
		if recover() != nil {
			result = map[string]any{"omitted": "metadata observation failed"}
		}
	}()
	return b.observer.Metadata(b.request, b.header, prefix, complete)
}
