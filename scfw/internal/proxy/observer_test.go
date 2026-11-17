// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestObserverPreservesTraffic(t *testing.T) {
	fixture, err := os.ReadFile("testdata/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]json.RawMessage
	if err := json.Unmarshal(fixture, &cases); err != nil {
		t.Fatal(err)
	}
	for _, encrypted := range []bool{false, true} {
		for _, compressed := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{true: "https", false: "http"}[encrypted], map[bool]string{true: "gzip", false: "identity"}[compressed]}, "/"), func(t *testing.T) {
				body := []byte(cases["observer/metadata"])
				if compressed {
					var b bytes.Buffer
					w := gzip.NewWriter(&b)
					_, _ = w.Write(body)
					_ = w.Close()
					body = b.Bytes()
				}

				target, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if compressed {
						w.Header().Set("Content-Encoding", "gzip")
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Set-Cookie", "response-cookie-canary")
					_, _ = w.Write(body[:1])
					w.(http.Flusher).Flush()
					_, _ = w.Write(body[1:])
				}), encrypted)
				var mutex sync.Mutex
				var events []map[string]any
				var samples atomic.Int32
				options.Observer = NewObserver(func(kind, _ string, fields map[string]any) {
					mutex.Lock()
					defer mutex.Unlock()
					if kind == "http.body" || kind == "http.response" || kind == "http.forward" {
						events = append(events, fields)
					}
				}, func(_ Request, _ http.Header, prefix []byte, complete bool) map[string]any {
					samples.Add(1)
					if !complete || !bytes.Equal(prefix, body) {
						t.Error("sample changed bytes or completeness")
					}
					return nil
				})
				server := startTestProxy(t, options)
				client := newProxyClient(t, server)
				request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target+"/metadata", nil)
				request.Header.Set("Authorization", "Bearer request-auth-canary")
				request.Header.Set("Accept-Encoding", "gzip")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				first := make([]byte, 1)
				if _, err := io.ReadFull(response.Body, first); err != nil {
					t.Fatal(err)
				}

				rest, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK || !bytes.Equal(append(first, rest...), body) {
					t.Fatal("changed forwarded status or bytes")
				}
				if samples.Load() != 1 {
					t.Fatalf("samples: %d", samples.Load())
				}
				mutex.Lock()
				defer mutex.Unlock()
				encoded, _ := json.Marshal(events)
				if bytes.Contains(encoded, []byte("request-auth-canary")) || bytes.Contains(encoded, []byte("response-cookie-canary")) {
					t.Fatal("observed non-allowlisted headers")
				}
			})
		}
	}
}

type observationTransportFunc func(*http.Request) (*http.Response, error)

func (f observationTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestObserverFailuresCannotChangeTransport(t *testing.T) {
	observer := NewObserver(func(string, string, map[string]any) { panic("recording failure") }, func(Request, http.Header, []byte, bool) map[string]any { panic("sample failure") })
	base := observationTransportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: 4, Body: io.NopCloser(strings.NewReader("data")), Request: r}, nil
	})
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.test/data", nil)
	response, err := ObserveTransport(base, observer, "publication").RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "data" {
		t.Fatal("callback failure changed transport")
	}
	want := errors.New("transport failure")
	_, err = ObserveTransport(observationTransportFunc(func(*http.Request) (*http.Response, error) { return nil, want }), observer, "publication").RoundTrip(request)
	if err != want {
		t.Fatal("changed transport error")
	}
}

func TestObserverCandidateBudgetAndPartialBodies(t *testing.T) {
	var completeSamples atomic.Int32
	observer := NewObserver(func(string, string, map[string]any) {}, func(_ Request, _ http.Header, _ []byte, complete bool) map[string]any {
		if complete {
			completeSamples.Add(1)
		}
		return nil
	})
	base := observationTransportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: 100, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 100))), Request: r}, nil
	})
	transport := ObserveTransport(base, observer, "manager")
	var responses []*http.Response
	for i := 0; i < 64; i++ {
		request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.test/pkg", nil)
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	if len(observer.slots) != 32 {
		t.Fatalf("candidate budget: %d", len(observer.slots))
	}
	for _, response := range responses {
		_, _ = response.Body.Read(make([]byte, 1))
		_ = response.Body.Close()
	}
	if len(observer.slots) != 0 || completeSamples.Load() != 0 {
		t.Fatal("leaked candidate slot or labeled partial body complete")
	}
}

type countingObservationReader struct {
	io.Reader
	reads *atomic.Int32
}

func (r countingObservationReader) Read(p []byte) (int, error) {
	r.reads.Add(1)
	return r.Reader.Read(p)
}

func TestObserverDoesNotReadAhead(t *testing.T) {
	var reads, samples atomic.Int32
	observer := NewObserver(func(string, string, map[string]any) {}, func(_ Request, _ http.Header, _ []byte, _ bool) map[string]any { samples.Add(1); return nil })
	base := observationTransportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: 4, Body: io.NopCloser(countingObservationReader{strings.NewReader("data"), &reads}), Request: r}, nil
	})
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.test/pkg", nil)
	response, err := ObserveTransport(base, observer, "manager").RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 0 {
		t.Fatal("read body during RoundTrip")
	}
	if _, err := response.Body.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || samples.Load() != 0 {
		t.Fatal("read ahead before consumer requested bytes")
	}
	_ = response.Body.Close()
	if reads.Load() != 1 {
		t.Fatal("drained body on Close")
	}
}

func TestObserverBodylessAndShortResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		body     io.ReadCloser
		size     int64
		complete bool
	}{
		{"bodyless", http.NoBody, 0, true},
		{"bodyless HEAD", http.NoBody, 100, true},
		{"short", io.NopCloser(strings.NewReader("data")), 100, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var observed map[string]any
			observer := NewObserver(func(kind, _ string, fields map[string]any) {
				if kind == "http.body" {
					observed = fields
				}
			}, nil)
			base := observationTransportFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: test.size, Body: test.body, Request: r}, nil
			})
			request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.test/pkg", nil)
			response, err := ObserveTransport(base, observer, "manager").RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || (test.name == "short" && string(body) != "data") || (test.name != "short" && len(body) != 0) {
				t.Fatal("changed response body")
			}
			_ = response.Body.Close()
			if observed["body_complete"] != test.complete || observed["digest_complete"] != test.complete {
				t.Fatalf("incorrect completion flags: %v", observed)
			}
		})
	}
}
