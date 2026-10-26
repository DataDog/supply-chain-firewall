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

	"github.com/elazarl/goproxy"
	"golang.org/x/net/http/httpproxy"
)

// testRegistryHost is the name test registries are reached by. It is not a
// loopback name, since httpproxy never routes loopback destinations through an
// upstream proxy.
const testRegistryHost = "registry.test"

func startTestProxy(t *testing.T, options Options) *Server {
	t.Helper()
	server, err := Start(context.Background(), options)
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

func TestRequestHookRejectsBeforeUpstream(t *testing.T) {
	var upstreamHits, responseHookCalls atomic.Int32
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHits.Add(1)
	}), true)
	options.RequestHooks = []RequestHook{
		func(_ context.Context, request *http.Request) error {
			if strings.HasSuffix(request.URL.Path, ".tgz") {
				return errors.New("package blocked by Supply Chain Firewall")
			}
			return nil
		},
	}
	options.ResponseHooks = []ResponseHook{
		func(context.Context, *http.Response) { responseHookCalls.Add(1) },
	}
	client := newProxyClient(t, startTestProxy(t, options))

	status, body := get(t, client, registryURL+"/left-pad/-/left-pad-1.0.0.tgz")
	if status != http.StatusForbidden || !strings.Contains(body, "package blocked by Supply Chain Firewall") {
		t.Errorf("response = %d %q, want 403 with the rejection reason", status, body)
	}
	if upstreamHits.Load() != 0 || responseHookCalls.Load() != 0 {
		t.Errorf("rejected request: upstream hits %d, response hook calls %d; want 0, 0", upstreamHits.Load(), responseHookCalls.Load())
	}

	// Other requests on the same tunnel still flow.
	if status, _ := get(t, client, registryURL+"/left-pad"); status != http.StatusOK || upstreamHits.Load() != 1 {
		t.Errorf("allowed request: status %d, upstream hits %d; want 200, 1", status, upstreamHits.Load())
	}
}

func TestRequestHooksRunInOrderUntilRejection(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	var calls []string
	options.RequestHooks = []RequestHook{
		func(context.Context, *http.Request) error { calls = append(calls, "first"); return nil },
		func(context.Context, *http.Request) error { calls = append(calls, "second"); return errors.New("no") },
		func(context.Context, *http.Request) error { calls = append(calls, "third"); return nil },
	}

	get(t, newProxyClient(t, startTestProxy(t, options)), registryURL)
	if got := strings.Join(calls, ","); got != "first,second" {
		t.Errorf("hooks ran %q, want %q", got, "first,second")
	}
}

func TestHooksObserveRequestsAndResponses(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"name":"left-pad"}`)
	}), true)

	var mutex sync.Mutex
	var requests, responses []string
	var observedBody strings.Builder
	options.RequestHooks = []RequestHook{
		func(_ context.Context, request *http.Request) error {
			mutex.Lock()
			defer mutex.Unlock()
			requests = append(requests, request.Method+" "+request.URL.String())
			return nil
		},
	}
	options.ResponseHooks = []ResponseHook{
		func(_ context.Context, response *http.Response) {
			mutex.Lock()
			defer mutex.Unlock()
			responses = append(responses, fmt.Sprintf("%d %s", response.StatusCode, response.Request.URL))
			// A hook may observe the body by wrapping it, as long as it streams.
			response.Body = struct {
				io.Reader
				io.Closer
			}{io.TeeReader(response.Body, &observedBody), response.Body}
		},
	}

	target := registryURL + "/left-pad"
	_, body := get(t, newProxyClient(t, startTestProxy(t, options)), target)

	mutex.Lock()
	defer mutex.Unlock()
	if len(requests) != 1 || requests[0] != "GET "+target {
		t.Errorf("observed requests = %q, want [%q]", requests, "GET "+target)
	}
	if len(responses) != 1 || responses[0] != "200 "+target {
		t.Errorf("observed responses = %q, want [%q]", responses, "200 "+target)
	}
	if body != `{"name":"left-pad"}` || observedBody.String() != body {
		t.Errorf("client body = %q, hook body = %q; want both %q", body, observedBody.String(), `{"name":"left-pad"}`)
	}
}

func TestResponsesStreamWithoutBuffering(t *testing.T) {
	tests := []struct {
		name          string
		contentLength bool
		responseHook  bool
	}{
		{name: "known length", contentLength: true},
		{name: "chunked", contentLength: false},
		{name: "known length with response hook", contentLength: true, responseHook: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseUpstream()

			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.contentLength {
					w.Header().Set("Content-Length", "10")
				}
				_, _ = io.WriteString(w, "first")
				w.(http.Flusher).Flush()
				<-release
				_, _ = io.WriteString(w, "-last")
			}), true)
			if tt.responseHook {
				options.ResponseHooks = []ResponseHook{func(context.Context, *http.Response) {}}
			}

			response, err := newProxyClient(t, startTestProxy(t, options)).Get(registryURL + "/artifact.tgz")
			if err != nil {
				t.Fatalf("Get() returned unexpected error: %v", err)
			}
			defer response.Body.Close()

			// The first chunk must arrive while upstream is still holding the rest.
			first := make([]byte, len("first"))
			readDone := make(chan error, 1)
			go func() {
				_, err := io.ReadFull(response.Body, first)
				readDone <- err
			}()
			select {
			case err := <-readDone:
				if err != nil || string(first) != "first" {
					t.Fatalf("first chunk = %q, %v; want %q", first, err, "first")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("proxy buffered the response instead of streaming it")
			}

			releaseUpstream()
			if rest, err := io.ReadAll(response.Body); err != nil || string(rest) != "-last" {
				t.Errorf("rest of body = %q, %v; want %q", rest, err, "-last")
			}
		})
	}
}

func TestCloseCancelsHookContext(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	hookContexts := make(chan context.Context, 1)
	options.RequestHooks = []RequestHook{func(ctx context.Context, _ *http.Request) error {
		hookContexts <- ctx
		return nil
	}}
	server := startTestProxy(t, options)

	get(t, newProxyClient(t, server), registryURL)
	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	if err := (<-hookContexts).Err(); !errors.Is(err, context.Canceled) {
		t.Errorf("hook context error after Close() = %v, want context.Canceled", err)
	}
}

func TestRedactURL(t *testing.T) {
	u, _ := url.Parse("https://user:token@registry.example/pkg/-/pkg-1.0.0.tgz?token=secret")
	if got, want := redactURL(u), "https://registry.example/pkg/-/pkg-1.0.0.tgz"; got != want {
		t.Errorf("redactURL() = %q, want %q", got, want)
	}
	if got := redactURL(nil); got != "" {
		t.Errorf("redactURL(nil) = %q, want empty", got)
	}
}

// startUpstreamProxy starts a forwarding proxy standing in for a corporate
// proxy, which dials registries with dial, and counts the requests and CONNECT
// tunnels it handles.
func startUpstreamProxy(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	upstream := goproxy.NewProxyHttpServer()
	upstream.Logger = proxyLogger{}
	upstream.Tr = &http.Transport{DialContext: dial}
	upstream.ConnectDial = func(network, address string) (net.Conn, error) {
		return dial(context.Background(), network, address)
	}
	upstream.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hits.Add(1)
		return goproxy.OkConnect, host
	})
	upstream.OnRequest().DoFunc(func(request *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		hits.Add(1)
		return request, nil
	})
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)
	return upstreamServer.URL, &hits
}

func TestChainsToUpstreamProxy(t *testing.T) {
	tests := []struct {
		name     string
		useTLS   bool
		upstream func(upstreamURL string) httpproxy.Config
		wantHits int32
	}{
		{
			name:     "https through HTTPS proxy",
			useTLS:   true,
			upstream: func(u string) httpproxy.Config { return httpproxy.Config{HTTPSProxy: u} },
			wantHits: 1,
		},
		{
			name:     "http through HTTP proxy",
			useTLS:   false,
			upstream: func(u string) httpproxy.Config { return httpproxy.Config{HTTPProxy: u} },
			wantHits: 1,
		},
		{
			name:     "no proxy match connects directly",
			useTLS:   true,
			upstream: func(u string) httpproxy.Config { return httpproxy.Config{HTTPSProxy: u, NoProxy: testRegistryHost} },
			wantHits: 0,
		},
		{
			name:     "no upstream connects directly",
			useTLS:   true,
			upstream: func(string) httpproxy.Config { return httpproxy.Config{} },
			wantHits: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), tt.useTLS)
			upstreamURL, hits := startUpstreamProxy(t, options.dialContext)
			options.Upstream = tt.upstream(upstreamURL)

			status, _ := get(t, newProxyClient(t, startTestProxy(t, options)), registryURL+"/pkg")
			if status != http.StatusOK || hits.Load() != tt.wantHits {
				t.Errorf("status %d, upstream proxy hits %d; want 200, %d", status, hits.Load(), tt.wantHits)
			}
		})
	}
}

func TestIgnoresEnvironmentProxySettings(t *testing.T) {
	// The proxy's own environment may point at a proxy (including itself, via a
	// nested invocation); only Options.Upstream may route outbound traffic.
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	upstreamURL, hits := startUpstreamProxy(t, options.dialContext)
	t.Setenv("HTTP_PROXY", upstreamURL)
	t.Setenv("HTTPS_PROXY", upstreamURL)

	status, _ := get(t, newProxyClient(t, startTestProxy(t, options)), registryURL)
	if status != http.StatusOK || hits.Load() != 0 {
		t.Errorf("status %d, environment proxy hits %d; want 200, 0", status, hits.Load())
	}
}
