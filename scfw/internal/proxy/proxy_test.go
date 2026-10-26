// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testRegistryHost is the name test registries are reached by. It is not a
// loopback name, since httpproxy never routes loopback destinations through an
// upstream proxy.
const testRegistryHost = "registry.test"

func startTestProxy(t *testing.T, options Options) *Server {
	t.Helper()
	server, err := Start(options)
	if err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// proxyRoots trusts only server's per-run CA, read back from the file handed
// to package managers.
func proxyRoots(t *testing.T, server *Server) *x509.CertPool {
	t.Helper()
	pemBytes, err := os.ReadFile(server.ClientConfig().CACertificatePath)
	if err != nil {
		t.Fatalf("ReadFile() returned unexpected error: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("proxy CA certificate file holds no certificate")
	}
	return roots
}

// newProxyClient returns a client that routes through server and trusts only
// its per-run CA.
func newProxyClient(t *testing.T, server *Server) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(server.ClientConfig().URL)
	if err != nil {
		t.Fatalf("url.Parse() returned unexpected error: %v", err)
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: proxyRoots(t, server), MinVersion: tls.VersionTLS12},
	}
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

// newTestRegistry starts a registry serving handler, over TLS with a
// certificate for testRegistryHost when useTLS is set. It returns the
// registry's base URL and options that make the proxy trust the registry and
// resolve testRegistryHost to it.
func newTestRegistry(t *testing.T, handler http.Handler, useTLS bool) (string, Options) {
	t.Helper()
	registry := httptest.NewUnstartedServer(handler)
	options := Options{dialContext: dialRegistryAs(registry.Listener.Addr().String())}
	scheme := "http"
	if useTLS {
		registryCA, err := newCertificateAuthority()
		if err != nil {
			t.Fatalf("newCertificateAuthority() returned unexpected error: %v", err)
		}
		leaf, err := registryCA.leafCertificate(testRegistryHost)
		if err != nil {
			t.Fatalf("leafCertificate() returned unexpected error: %v", err)
		}
		registry.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
		registry.StartTLS()
		options.upstreamRootCAs = x509.NewCertPool()
		options.upstreamRootCAs.AddCert(registryCA.certificate)
		scheme = "https"
	} else {
		registry.Start()
	}
	t.Cleanup(registry.Close)

	_, port, _ := net.SplitHostPort(registry.Listener.Addr().String())
	return scheme + "://" + net.JoinHostPort(testRegistryHost, port), options
}

// dialRegistryAs resolves testRegistryHost to address and dials anything else normally.
func dialRegistryAs(address string) func(context.Context, string, string) (net.Conn, error) {
	var dialer net.Dialer
	_, registryPort, _ := net.SplitHostPort(address)
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(target); err == nil && host == testRegistryHost && port == registryPort {
			target = address
		}
		return dialer.DialContext(ctx, network, target)
	}
}

// openTunnel opens a raw CONNECT tunnel to host through server.
func openTunnel(t *testing.T, server *Server, host string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.ClientConfig().URL, "http://"))
	if err != nil {
		t.Fatalf("Dial() returned unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %v, %v; want 200", response, err)
	}
	return conn, reader
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
	firstPEM, _ := os.ReadFile(first.CACertificatePath)
	secondPEM, _ := os.ReadFile(second.CACertificatePath)
	if first.CACertificatePath == second.CACertificatePath || string(firstPEM) == string(secondPEM) {
		t.Error("two proxies share a CA certificate")
	}
}

func TestCloseRemovesCertificateAndStopsListening(t *testing.T) {
	server := startTestProxy(t, Options{})
	config := server.ClientConfig()

	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Errorf("second Close() returned unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Dir(config.CACertificatePath)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("certificate directory still exists after Close(): %v", err)
	}
	if conn, err := net.DialTimeout("tcp", strings.TrimPrefix(config.URL, "http://"), time.Second); err == nil {
		_ = conn.Close()
		t.Error("proxy still accepts connections after Close()")
	}
}

func TestProxiesPlainHTTP(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}), false)
	server := startTestProxy(t, options)

	if status, body := get(t, newProxyClient(t, server), registryURL); status != http.StatusOK || body != "plain" {
		t.Errorf("response = %d %q, want 200 %q", status, body, "plain")
	}
}

func TestPassesContentEncodingThrough(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not really gzip")
	}), false)
	server := startTestProxy(t, options)

	request, _ := http.NewRequest(http.MethodGet, registryURL, nil)
	request.Header.Set("Accept-Encoding", "gzip")
	// The client must not transparently decode, to see what the proxy forwards.
	client := newProxyClient(t, server)
	client.Transport.(*http.Transport).DisableCompression = true
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

func TestCertificateFileHasRestrictivePermissions(t *testing.T) {
	path := startTestProxy(t, Options{}).ClientConfig().CACertificatePath

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) returned unexpected error: %v", path, err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("certificate file mode = %o, want 600", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat(%q) returned unexpected error: %v", filepath.Dir(path), err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("certificate directory mode = %o, want 700", mode)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned unexpected error: %v", path, err)
	}
	if strings.Contains(string(contents), "PRIVATE KEY") {
		t.Error("certificate file contains a private key")
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("certificate directory holds %d entries, want only the CA certificate", len(entries))
	}
}

func TestInterceptsHTTPSWithPerRunCA(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}), true)
	server := startTestProxy(t, options)

	response, err := newProxyClient(t, server).Get(registryURL + "/pkg")
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK || string(body) != "hello from /pkg" {
		t.Errorf("response = %d %q, want 200 %q", response.StatusCode, body, "hello from /pkg")
	}
	issuer := response.TLS.PeerCertificates[0].Issuer.CommonName
	if !strings.HasPrefix(issuer, "Supply Chain Firewall ephemeral proxy CA") {
		t.Errorf("intercepted certificate issuer = %q, want the per-run proxy CA", issuer)
	}
}

func TestUpstreamTLSIsVerified(t *testing.T) {
	var upstreamHits atomic.Int32
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHits.Add(1)
	}), true)
	// Without the registry's roots, the proxy must refuse the registry rather
	// than silently intercepting an unverified connection.
	options.upstreamRootCAs = nil
	server := startTestProxy(t, options)

	if response, err := newProxyClient(t, server).Get(registryURL); err == nil {
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Error("Get() through proxy to an untrusted registry succeeded")
		}
	}
	if upstreamHits.Load() != 0 {
		t.Errorf("untrusted registry served %d requests, want 0", upstreamHits.Load())
	}
}

func TestConcurrentHTTPSRequests(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}), true)
	client := newProxyClient(t, startTestProxy(t, options))

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			path := fmt.Sprintf("/pkg-%d", i)
			response, err := client.Get(registryURL + path)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			if body, _ := io.ReadAll(response.Body); string(body) != path {
				t.Errorf("body = %q, want %q", body, path)
			}
		})
	}
	wg.Wait()
}

func TestDiagnosticsDoNotLogRequestData(t *testing.T) {
	logs := captureDebugLogs(t)
	server := startTestProxy(t, Options{})

	conn, _ := openTunnel(t, server, "registry.example:443")
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "registry.example", RootCAs: proxyRoots(t, server), MinVersion: tls.VersionTLS12})
	// A control byte makes the header unparseable, so goproxy reports an error
	// that quotes the whole header.
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: registry.example\r\nAuthorization: Bearer secret-token\x01\r\n\r\n")
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(tlsConn)
	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	if strings.Contains(logs.String(), "secret-token") {
		t.Errorf("logs contain the Authorization token:\n%s", logs.String())
	}
}
