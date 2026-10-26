// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func startTestProxy(t *testing.T, options Options) *Server {
	t.Helper()
	server, err := Start(options)
	if err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// newProxyClient returns a client that routes through server, starting from
// base's transport so tests can choose which certificates the client trusts.
func newProxyClient(t *testing.T, server *Server, base *http.Transport) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(server.ClientConfig().URL)
	if err != nil {
		t.Fatalf("url.Parse() returned unexpected error: %v", err)
	}
	transport := base.Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// get fetches target through client and returns the status and body.
func get(t *testing.T, client *http.Client, target string) (int, string) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("Get(%q) returned unexpected error: %v", target, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response body returned unexpected error: %v", err)
	}
	return response.StatusCode, string(body)
}

// captureDebugLogs records everything logged through slog until the test ends.
func captureDebugLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

type lockedBuffer struct {
	mutex   sync.Mutex
	builder strings.Builder
}

func (buffer *lockedBuffer) Write(p []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.builder.Write(p)
}

func (buffer *lockedBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.builder.String()
}

func TestStartListensOnLoopbackEphemeralPort(t *testing.T) {
	server := startTestProxy(t, Options{})

	proxyURL, err := url.Parse(server.ClientConfig().URL)
	if err != nil {
		t.Fatalf("url.Parse() returned unexpected error: %v", err)
	}
	if proxyURL.Scheme != "http" || proxyURL.Hostname() != "127.0.0.1" {
		t.Errorf("proxy URL = %q, want http://127.0.0.1:<port>", proxyURL)
	}
	if port := proxyURL.Port(); port == "" || port == "0" {
		t.Errorf("proxy port = %q, want an OS-assigned port", port)
	}
}

func TestStartCreatesDistinctProxiesPerCall(t *testing.T) {
	first := startTestProxy(t, Options{}).ClientConfig()
	second := startTestProxy(t, Options{}).ClientConfig()

	if first.URL == second.URL {
		t.Error("two proxies share a URL")
	}
}

func TestCloseStopsListening(t *testing.T) {
	server := startTestProxy(t, Options{})
	config := server.ClientConfig()

	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Errorf("second Close() returned unexpected error: %v", err)
	}

	if conn, err := net.DialTimeout("tcp", strings.TrimPrefix(config.URL, "http://"), time.Second); err == nil {
		_ = conn.Close()
		t.Error("proxy still accepts connections after Close()")
	}
}

func TestProxiesPlainHTTP(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}))
	t.Cleanup(registry.Close)
	server := startTestProxy(t, Options{})

	if status, body := get(t, newProxyClient(t, server, &http.Transport{}), registry.URL); status != http.StatusOK || body != "plain" {
		t.Errorf("response = %d %q, want 200 %q", status, body, "plain")
	}
}

func TestTunnelsHTTPS(t *testing.T) {
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	t.Cleanup(registry.Close)
	server := startTestProxy(t, Options{})

	// The client trusts only the registry's own certificate, so a successful
	// request proves the proxy relayed the TLS session end to end.
	client := newProxyClient(t, server, registry.Client().Transport.(*http.Transport))
	response, err := client.Get(registry.URL)
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "secure" {
		t.Errorf("response = %d %q, want 200 %q", response.StatusCode, body, "secure")
	}
	if !response.TLS.PeerCertificates[0].Equal(registry.Certificate()) {
		t.Error("client did not see the registry's own certificate")
	}
}

func TestPassesContentEncodingThrough(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not really gzip")
	}))
	t.Cleanup(registry.Close)
	server := startTestProxy(t, Options{})

	request, _ := http.NewRequest(http.MethodGet, registry.URL, nil)
	request.Header.Set("Accept-Encoding", "gzip")
	// The client must not transparently decode, to see what the proxy forwards.
	client := newProxyClient(t, server, &http.Transport{DisableCompression: true})
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do() returned unexpected error: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)

	if got := response.Header.Get("X-Accept-Encoding"); got != "gzip" {
		t.Errorf("upstream saw Accept-Encoding %q, want %q", got, "gzip")
	}
	if got := response.Header.Get("Content-Encoding"); got != "gzip" || string(body) != "not really gzip" {
		t.Errorf("client got Content-Encoding %q body %q; want the upstream bytes unchanged", got, body)
	}
}

func TestProxyLoggerOmitsInterpolatedValues(t *testing.T) {
	logs := captureDebugLogs(t)

	proxyLogger{}.Printf("[%03d] WARN: Cannot read request %v", 1, "Authorization: Bearer secret-token")

	if got := logs.String(); strings.Contains(got, "secret-token") || !strings.Contains(got, "Cannot read request") {
		t.Errorf("logs = %q, want the message template without its values", got)
	}
}
