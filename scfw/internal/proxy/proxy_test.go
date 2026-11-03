// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bufio"
	"bytes"
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
		func(_ context.Context, request Request) (ResponseHook, error) {
			if strings.HasSuffix(request.URL.Path, ".tgz") {
				return nil, errors.New("package blocked by Supply Chain Firewall")
			}
			return func(context.Context, Response) (*ResponseBodyHook, error) {
				responseHookCalls.Add(1)
				return nil, nil
			}, nil
		},
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

func TestResponseBodyHookFinishesBeforeDeclaredLengthIsDelivered(t *testing.T) {
	const metadataBody = `{"files":[{"filename":"project-1.0.tar.gz","url":"/objects/opaque"}]}`
	endStream := make(chan struct{})
	defer close(endStream)
	var artifactHits atomic.Int32
	registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/objects/opaque" {
			artifactHits.Add(1)
			_, _ = io.WriteString(w, "artifact bytes")
			return
		}
		if request.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s, want HTTP/2", request.Proto)
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(metadataBody)))
		_, _ = io.WriteString(w, metadataBody)
		w.(http.Flusher).Flush()
		// Deliver all declared bytes, but withhold HTTP/2 END_STREAM until the
		// installer has made its next request on a separate connection.
		select {
		case <-endStream:
		case <-request.Context().Done():
		}
	}))
	registry.EnableHTTP2 = true
	registry.StartTLS()
	t.Cleanup(registry.Close)
	roots := x509.NewCertPool()
	roots.AddCert(registry.Certificate())
	var processed atomic.Bool
	server := startTestProxy(t, Options{
		upstreamRootCAs: roots,
		RequestHooks: []RequestHook{func(_ context.Context, request Request) (ResponseHook, error) {
			if request.URL.Path == "/objects/opaque" && processed.Load() {
				return nil, errors.New("blocked advertised artifact")
			}
			if request.URL.Path != "/simple/project/" {
				return nil, nil
			}
			return func(context.Context, Response) (*ResponseBodyHook, error) {
				return &ResponseBodyHook{MaxBytes: 1024, Handle: func(_ context.Context, response Response) error {
					if string(response.Body) != metadataBody {
						t.Errorf("observed %q, want complete metadata body", response.Body)
					}
					processed.Store(true)
					return nil
				}}, nil
			}, nil
		}},
	})
	if status, body := get(t, newProxyClient(t, server), registry.URL+"/simple/project/"); status != http.StatusOK || body != metadataBody {
		t.Fatalf("metadata response = %d %q; want original bytes", status, body)
	}
	if status, _ := get(t, newProxyClient(t, server), registry.URL+"/objects/opaque"); status != http.StatusForbidden || artifactHits.Load() != 0 {
		t.Fatalf("artifact status=%d upstream hits=%d; want 403, 0", status, artifactHits.Load())
	}
}

func TestResponseHooksKeepConcurrentBodiesAndCopiesIsolated(t *testing.T) {
	var inspected atomic.Int32
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Request") != "original" {
			t.Error("request hook mutated the forwarded request")
		}
		w.Header().Set("X-Response", "original")
		_, _ = io.WriteString(w, request.URL.Path)
	}), true)
	for range 2 {
		options.RequestHooks = append(options.RequestHooks, func(_ context.Context, request Request) (ResponseHook, error) {
			if request.Header.Get("X-Request") != "original" {
				t.Error("request hooks shared mutable headers")
			}
			request.Header.Set("X-Request", "changed")
			if request.URL.Path == "/unobserved" {
				return nil, nil
			}
			expectedPath := request.URL.Path
			return func(_ context.Context, response Response) (*ResponseBodyHook, error) {
				if response.Request.URL.Path != expectedPath || response.Header.Get("X-Response") != "original" || response.Body != nil {
					t.Errorf("wrong response snapshot for %s: %#v", expectedPath, response)
				}
				response.Header.Set("X-Response", "changed")
				return &ResponseBodyHook{MaxBytes: 1024, Handle: func(_ context.Context, response Response) error {
					if !bytes.Equal(response.Body, []byte(expectedPath)) || response.Header.Get("X-Response") != "original" ||
						response.Request.Header.Get("X-Request") != "original" {
						t.Errorf("body or headers leaked between hooks for %s: %#v", expectedPath, response)
					}
					response.Body[0] = '!'
					response.Header.Set("X-Response", "changed")
					response.Request.Header.Set("X-Request", "changed")
					inspected.Add(1)
					return nil
				}}, nil
			}, nil
		})
	}
	client := newProxyClient(t, startTestProxy(t, options))
	var group sync.WaitGroup
	for index := range 12 {
		group.Go(func() {
			target := fmt.Sprintf("/metadata-%d", index)
			if index == 0 {
				target = "/unobserved"
			}
			request, _ := http.NewRequest(http.MethodGet, registryURL+target, nil)
			request.Header.Set("X-Request", "original")
			response, err := client.Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != target || response.Header.Get("X-Response") != "original" {
				t.Errorf("forwarded %s = %q, %v, headers=%v", target, body, err, response.Header)
			}
		})
	}
	group.Wait()
	if inspected.Load() != 22 {
		t.Fatalf("body hook calls = %d; want 22", inspected.Load())
	}
}

func TestResponseBodyHookCompletesBeforeResponseIsForwarded(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", useTLS), func(t *testing.T) {
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "metadata bytes")
			}), useTLS)
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			defer finish()
			options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) {
				return func(context.Context, Response) (*ResponseBodyHook, error) {
					return &ResponseBodyHook{MaxBytes: 1024, Handle: func(ctx context.Context, response Response) error {
						if string(response.Body) != "metadata bytes" {
							t.Errorf("body = %q; want complete metadata", response.Body)
						}
						close(started)
						select {
						case <-release:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}}, nil
				}, nil
			}}
			client := newProxyClient(t, startTestProxy(t, options))
			result := make(chan error, 1)
			go func() {
				response, err := client.Get(registryURL)
				if err == nil {
					defer response.Body.Close()
					body, readErr := io.ReadAll(response.Body)
					if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "metadata bytes" {
						err = fmt.Errorf("response = %d %q, %v", response.StatusCode, body, readErr)
					}
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("body hook did not run")
			}
			select {
			case err := <-result:
				t.Fatalf("response forwarded before hook finished: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			finish()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResponseInspectionFailuresDoNotForwardBody(t *testing.T) {
	for _, test := range []struct {
		name               string
		length             string
		maxBytes           int64
		headerErr, bodyErr bool
	}{
		{name: "known oversized", length: "6", maxBytes: 5},
		{name: "chunked oversized", maxBytes: 5},
		{name: "truncated", length: "8", maxBytes: 8},
		{name: "invalid limit", length: "6"},
		{name: "header failure", length: "6", maxBytes: 8, headerErr: true},
		{name: "body failure", length: "6", maxBytes: 8, bodyErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.length != "" {
					w.Header().Set("Content-Length", test.length)
				}
				w.(http.Flusher).Flush()
				_, _ = io.WriteString(w, "secret")
			}), true)
			var bodyCalls atomic.Int32
			options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) {
				return func(context.Context, Response) (*ResponseBodyHook, error) {
					if test.headerErr {
						return nil, errors.New("secret")
					}
					return &ResponseBodyHook{MaxBytes: test.maxBytes, Handle: func(context.Context, Response) error {
						bodyCalls.Add(1)
						if test.bodyErr {
							return errors.New("secret")
						}
						return nil
					}}, nil
				}, nil
			}}
			status, body := get(t, newProxyClient(t, startTestProxy(t, options)), registryURL)
			if status != http.StatusBadGateway || strings.Contains(body, "secret") {
				t.Fatalf("response = %d %q; want 502 without upstream bytes or hook error", status, body)
			}
			if !test.bodyErr && bodyCalls.Load() != 0 {
				t.Error("body hook processed an incomplete or oversized response")
			}
		})
	}
}

func TestCloseCancelsResponseBuffering(t *testing.T) {
	started := make(chan struct{})
	upstreamCanceled := make(chan struct{})
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
		close(upstreamCanceled)
	}), false)
	options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) {
		return func(context.Context, Response) (*ResponseBodyHook, error) {
			return &ResponseBodyHook{MaxBytes: 1024, Handle: func(context.Context, Response) error {
				t.Error("incomplete response was processed")
				return nil
			}}, nil
		}, nil
	}}
	server := startTestProxy(t, options)
	client := newProxyClient(t, server)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if response, err := client.Get(registryURL); err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("metadata request did not start")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []chan struct{}{upstreamCanceled, finished} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("buffering did not stop after proxy shutdown")
		}
	}
}

func TestRequestHooksRunInOrderUntilRejection(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	var calls []string
	options.RequestHooks = []RequestHook{
		func(context.Context, Request) (ResponseHook, error) { calls = append(calls, "first"); return nil, nil },
		func(context.Context, Request) (ResponseHook, error) {
			calls = append(calls, "second")
			return nil, errors.New("no")
		},
		func(context.Context, Request) (ResponseHook, error) { calls = append(calls, "third"); return nil, nil },
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
	options.RequestHooks = []RequestHook{
		func(_ context.Context, request Request) (ResponseHook, error) {
			mutex.Lock()
			requests = append(requests, request.Method+" "+request.URL.String())
			mutex.Unlock()
			return func(_ context.Context, response Response) (*ResponseBodyHook, error) {
				mutex.Lock()
				defer mutex.Unlock()
				responses = append(responses, fmt.Sprintf("%d %s", response.StatusCode, response.Request.URL.String()))
				return nil, nil
			}, nil
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
	if body != `{"name":"left-pad"}` {
		t.Errorf("client body = %q, want %q", body, `{"name":"left-pad"}`)
	}
}

func TestRequestBodyReachesUpstreamUnchanged(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}), true)
	options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) { return nil, nil }}
	client := newProxyClient(t, startTestProxy(t, options))

	response, err := client.Post(registryURL+"/-/publish", "application/json", strings.NewReader(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatalf("Post() returned unexpected error: %v", err)
	}
	defer response.Body.Close()
	if body, _ := io.ReadAll(response.Body); string(body) != `{"name":"left-pad"}` {
		t.Errorf("registry received body %q, want %q", body, `{"name":"left-pad"}`)
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
				options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) {
					return func(context.Context, Response) (*ResponseBodyHook, error) { return nil, nil }, nil
				}}
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

func TestCloseCancelsRunningHooks(t *testing.T) {
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	hookStarted, hookCanceled := make(chan struct{}), make(chan struct{})
	options.RequestHooks = []RequestHook{
		func(ctx context.Context, _ Request) (ResponseHook, error) {
			close(hookStarted)
			<-ctx.Done()
			close(hookCanceled)
			return nil, ctx.Err()
		},
	}
	server := startTestProxy(t, options)
	client := newProxyClient(t, server)
	go func() {
		if response, err := client.Get(registryURL); err == nil {
			_ = response.Body.Close()
		}
	}()

	select {
	case <-hookStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("request hook never ran")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	select {
	case <-hookCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not cancel the running hook")
	}
}

func TestCloseCancelsInFlightUpstreamRequests(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	testDone := make(chan struct{})
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(upstreamCanceled)
		case <-testDone:
		}
	}), true)
	// Registered after the registry, so it runs first and unblocks the handler
	// even if the proxy leaks the request.
	t.Cleanup(func() { close(testDone) })
	server := startTestProxy(t, options)

	response, err := newProxyClient(t, server).Get(registryURL + "/artifact.tgz")
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}
	defer response.Body.Close()
	if _, err := io.ReadFull(response.Body, make([]byte, len("first"))); err != nil {
		t.Fatalf("reading first chunk returned unexpected error: %v", err)
	}

	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was still active after Close() returned")
	}
}

func TestClientCancellationAbortsUpstreamRequest(t *testing.T) {
	upstreamStarted, upstreamCanceled := make(chan struct{}), make(chan struct{})
	testDone := make(chan struct{})
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(upstreamStarted)
		select {
		case <-r.Context().Done():
			close(upstreamCanceled)
		case <-testDone:
		}
	}), false)
	// Registered after the registry, so it runs first and unblocks the handler
	// even if the proxy leaks the request.
	t.Cleanup(func() { close(testDone) })
	client := newProxyClient(t, startTestProxy(t, options))

	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, registryURL, nil)
	go func() {
		if response, err := client.Do(request); err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-upstreamStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached upstream")
	}

	cancel()
	select {
	case <-upstreamCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request kept running after the client canceled it")
	}
}

func TestClientDisconnectCancelsBufferedResponse(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", useTLS), func(t *testing.T) {
			started, canceled, testDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				_, _ = io.WriteString(w, "partial metadata")
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-request.Context().Done():
					close(canceled)
				case <-testDone:
				}
			}), useTLS)
			t.Cleanup(func() { close(testDone) })
			options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) {
				return func(context.Context, Response) (*ResponseBodyHook, error) {
					return &ResponseBodyHook{MaxBytes: 1024, Handle: func(context.Context, Response) error {
						t.Error("incomplete metadata was processed")
						return nil
					}}, nil
				}, nil
			}}
			client := newProxyClient(t, startTestProxy(t, options))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, registryURL, nil)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				if response, err := client.Do(request); err == nil {
					_ = response.Body.Close()
				}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream metadata request did not start")
			}
			cancel()
			for _, done := range []chan struct{}{canceled, finished} {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("buffering retained an upstream request after the client disconnected")
				}
			}
		})
	}
}

func TestTruncatedStreamingResponseDoesNotComplete(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("TLS=%t", useTLS), func(t *testing.T) {
			partial := strings.Repeat("partial artifact", 512)
			finish := make(chan struct{})
			var finishOnce sync.Once
			finishResponse := func() { finishOnce.Do(func() { close(finish) }) }
			defer finishResponse()
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = io.WriteString(w, partial)
				w.(http.Flusher).Flush()
				<-finish
				// Close upstream without the final chunk that completes its body.
				panic(http.ErrAbortHandler)
			}), useTLS)
			response, err := newProxyClient(t, startTestProxy(t, options)).Get(registryURL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			finishResponse()
			body, err := io.ReadAll(response.Body)
			if string(body) != partial || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("body length = %d, error = %v; want %d partial bytes and unexpected EOF", len(body), err, len(partial))
			}
		})
	}
}

func TestUpgradedTunnelClosesAfterUpstream(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("TLS=%t", useTLS), func(t *testing.T) {
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				connection, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				_, _ = io.WriteString(connection, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\npayload")
			}), useTLS)
			server := startTestProxy(t, options)
			target, _ := url.Parse(registryURL)
			connection, _ := openTunnel(t, server, target.Host)
			if useTLS {
				connection = tls.Client(connection, &tls.Config{
					RootCAs: proxyRoots(t, server), ServerName: testRegistryHost, MinVersion: tls.VersionTLS12,
				})
				defer connection.Close()
			}
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := fmt.Fprintf(connection, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", target.Host); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(connection)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("status = %d, want 101", response.StatusCode)
			}
			body, err := io.ReadAll(reader)
			if err != nil || string(body) != "payload" {
				t.Fatalf("upgraded body = %q, error = %v; want payload followed by EOF", body, err)
			}
		})
	}
}

func TestCloseTerminatesOpenTunnels(t *testing.T) {
	server := startTestProxy(t, Options{})
	conn, reader := openTunnel(t, server, "registry.npmjs.org:443")

	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return while a tunnel was open")
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var netErr net.Error
	if _, err := io.ReadAll(reader); errors.As(err, &netErr) && netErr.Timeout() {
		t.Error("tunnel stayed open after Close()")
	}
}

func TestParentContextCancellationAbortsRequests(t *testing.T) {
	var upstreamHits atomic.Int32
	registryURL, options := newTestRegistry(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHits.Add(1)
	}), false)
	ctx, cancel := context.WithCancel(context.Background())
	server, err := Start(ctx, options)
	if err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	cancel()
	if response, err := newProxyClient(t, server).Get(registryURL); err == nil {
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Error("request succeeded after the proxy's context was canceled")
		}
	}
	if upstreamHits.Load() != 0 {
		t.Errorf("upstream served %d requests after cancellation, want 0", upstreamHits.Load())
	}
}
