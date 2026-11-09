// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func stalledTLSConnection(t *testing.T) (net.Conn, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	started, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		var first [1]byte
		_, _ = server.Read(first[:])
		close(started)
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, started, closed
}

func assertTLSConnectionClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("failed TLS connection was not closed")
	}
}

func TestHTTPSProxyHandshakeTimeout(t *testing.T) {
	for _, explicitRoute := range []bool{false, true} {
		name := "default"
		if explicitRoute {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			// Custom dialers must preserve the timeout inherited from the
			// default transport. This test does not run in parallel.
			original := http.DefaultTransport
			defaults := original.(*http.Transport).Clone()
			defaults.TLSHandshakeTimeout = 40 * time.Millisecond
			http.DefaultTransport = defaults
			defer func() { http.DefaultTransport = original; defaults.CloseIdleConnections() }()
			client, _, closed := stalledTLSConnection(t)
			upstream, _ := url.Parse("https://proxy.example:443")
			options := Options{dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			if explicitRoute {
				options.RouteForRequest = func(Request) (*OutboundRoute, error) { return &OutboundRoute{ProxyURL: upstream}, nil }
			} else {
				options.ProxyForURL = func(*url.URL) (*url.URL, error) { return upstream, nil }
			}
			transport := NewTransport(options)
			defer transport.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://registry.example/simple/", nil)
			response, err := (&http.Client{Transport: transport}).Do(request)
			if response != nil {
				_ = response.Body.Close()
			}
			if err == nil || ctx.Err() != nil {
				t.Fatalf("TLS handshake timeout ignored: %v", err)
			}
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("not a timeout error: %v", err)
			}
			assertTLSConnectionClosed(t, closed)
		})
	}
}

func TestHTTPSProxyDialerPreservesContext(t *testing.T) {
	for _, test := range []struct {
		name                string
		handshake, deadline time.Duration
		cancel              bool
	}{
		{name: "earlier deadline", handshake: 3 * time.Second, deadline: 40 * time.Millisecond},
		{name: "zero handshake timeout", deadline: 75 * time.Millisecond},
		{name: "cancellation", handshake: 3 * time.Second, deadline: 3 * time.Second, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, started, closed := stalledTLSConnection(t)
			upstream, _ := url.Parse("https://proxy.example:443")
			transport := NewTransport(Options{dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }})
			defer transport.CloseIdleConnections()
			configured := transport.routeTransport(&OutboundRoute{ProxyURL: upstream})
			configured.TLSHandshakeTimeout = test.handshake
			ctx, cancel := context.WithTimeout(context.Background(), test.deadline)
			defer cancel()
			if test.cancel {
				go func() { <-started; cancel() }()
			}
			connection, err := configured.DialTLSContext(ctx, "tcp", upstream.Host)
			if connection != nil {
				_ = connection.Close()
			}
			want := error(context.DeadlineExceeded)
			if test.cancel {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatalf("dialer context: %v", err)
			}
			assertTLSConnectionClosed(t, closed)
		})
	}
}
