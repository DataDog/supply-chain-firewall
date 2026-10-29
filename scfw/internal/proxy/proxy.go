// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package proxy provides a short-lived, loopback-only HTTP/HTTPS interception
// proxy that lets SCFW observe, and reject, a package manager's registry traffic.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"golang.org/x/net/http/httpproxy"
)

const (
	// listenAddress restricts the proxy to loopback on an OS-assigned port.
	listenAddress = "127.0.0.1:0"

	certificateFileName = "ca.pem"

	// maxIdleConnsPerHost keeps upstream connections for reuse: package
	// managers fetch many artifacts concurrently from one or two registries,
	// and the default of 2 would reconnect after every burst.
	maxIdleConnsPerHost = 32
)

// Request describes a request observed by the proxy. It is a copy: hooks see
// what is being requested, but cannot change the request or read its body.
type Request struct {
	Method string
	URL    url.URL
}

// Response describes an upstream response observed by the proxy. It is a
// copy: the proxy alone streams the response body back to the client.
type Response struct {
	Request    Request
	StatusCode int
}

// RequestHook observes a request before it is sent upstream. ctx is canceled
// when the client abandons the request or the proxy closes. Returning a
// non-nil error rejects the request with HTTP 403 Forbidden and the error text
// as body, without contacting upstream.
type RequestHook func(ctx context.Context, request Request) error

// ResponseHook observes an upstream response before it is streamed back to the
// client. ctx is canceled when the client abandons the request or the proxy
// closes.
type ResponseHook func(ctx context.Context, response Response)

// Options configures a proxy.
type Options struct {
	// Upstream is the proxy configuration that was in effect before SCFW, as
	// supplied by the package manager integration. Outbound requests honor it so
	// corporate proxies keep working. The zero value connects directly; the
	// process environment is never consulted, which prevents the proxy from
	// routing to itself through the variables it sets for its child.
	Upstream httpproxy.Config

	// RequestHooks run, in order, for each request. The first rejection wins.
	RequestHooks []RequestHook

	// ResponseHooks run, in order, for each upstream response.
	ResponseHooks []ResponseHook

	// upstreamRootCAs and dialContext let tests reach local upstream servers;
	// nil means the system roots and the default dialer.
	upstreamRootCAs *x509.CertPool
	dialContext     func(ctx context.Context, network, address string) (net.Conn, error)
}

// ClientConfig is what a package manager needs to route its traffic through
// the proxy and trust its interception certificates.
type ClientConfig struct {
	// URL is the proxy URL, used for both HTTP and HTTPS traffic.
	URL string

	// CACertificatePath is a PEM file holding the per-run CA certificate.
	CACertificatePath string
}

// Server is a running proxy with its own per-run certificate authority.
type Server struct {
	listener     net.Listener
	httpServer   *http.Server
	transport    *http.Transport
	clientConfig ClientConfig
	served       chan error

	// ctx is the context of every proxied request and hook. It is canceled
	// when the caller's context is canceled or Close is called, aborting
	// in-flight upstream exchanges.
	ctx    context.Context
	cancel context.CancelFunc

	// connections holds every open client connection, including the CONNECT
	// tunnels goproxy hijacks, which http.Server stops tracking.
	connectionsMutex sync.Mutex
	connections      map[net.Conn]struct{}

	closeOnce sync.Once
	closeErr  error
}

// Start creates a per-run CA, writes its public certificate to a private
// temporary directory, and starts a proxy on a loopback ephemeral port. The
// caller must call Close once the proxied process has exited. Canceling ctx
// cancels in-flight requests, but does not release the proxy's resources.
func Start(ctx context.Context, options Options) (*Server, error) {
	ca, err := newCertificateAuthority()
	if err != nil {
		return nil, fmt.Errorf("create proxy certificate authority: %w", err)
	}

	// os.MkdirTemp creates the directory with mode 0700.
	certificateDir, err := os.MkdirTemp("", "scfw-proxy-")
	if err != nil {
		return nil, fmt.Errorf("create proxy certificate directory: %w", err)
	}
	certificatePath := filepath.Join(certificateDir, certificateFileName)
	if err := os.WriteFile(certificatePath, ca.pem, 0o600); err != nil {
		_ = os.RemoveAll(certificateDir)
		return nil, fmt.Errorf("write proxy CA certificate: %w", err)
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		_ = os.RemoveAll(certificateDir)
		return nil, fmt.Errorf("listen for proxy connections: %w", err)
	}
	proxyURL := "http://" + listener.Addr().String()

	serverCtx, cancel := context.WithCancel(ctx)
	server := &Server{
		listener:     listener,
		transport:    newUpstreamTransport(options),
		clientConfig: ClientConfig{URL: proxyURL, CACertificatePath: certificatePath},
		served:       make(chan error, 1),
		ctx:          serverCtx,
		cancel:       cancel,
		connections:  make(map[net.Conn]struct{}),
	}
	server.httpServer = &http.Server{
		Handler:           server.newHandler(ca, options.RequestHooks, options.ResponseHooks),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
		ConnState:         server.trackConnection,
	}

	go func() {
		server.served <- server.httpServer.Serve(server.listener)
	}()

	slog.Debug("started package manager proxy", "url", proxyURL)
	return server, nil
}

// ClientConfig returns the configuration package managers need to use the proxy.
func (server *Server) ClientConfig() ClientConfig {
	return server.clientConfig
}

// Close stops the proxy and removes its temporary certificate material. It
// cancels in-flight requests and hooks and closes every connection, including
// open CONNECT tunnels. Close is idempotent.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		server.cancel()
		closeErr := server.httpServer.Close()
		server.connectionsMutex.Lock()
		for conn := range server.connections {
			_ = conn.Close()
		}
		server.connectionsMutex.Unlock()
		server.transport.CloseIdleConnections()
		serveErr := <-server.served
		removeErr := os.RemoveAll(filepath.Dir(server.clientConfig.CACertificatePath))

		var errs []error
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("shut down proxy: %w", closeErr))
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("serve proxy: %w", serveErr))
		}
		if removeErr != nil {
			errs = append(errs, fmt.Errorf("remove proxy certificate directory: %w", removeErr))
		}
		server.closeErr = errors.Join(errs...)
		slog.Debug("stopped package manager proxy")
	})
	return server.closeErr
}

// trackConnection records open client connections for Close. Hijacked
// connections are never reported closed, so they stay recorded until Close.
func (server *Server) trackConnection(conn net.Conn, state http.ConnState) {
	server.connectionsMutex.Lock()
	defer server.connectionsMutex.Unlock()
	switch state {
	case http.StateNew:
		server.connections[conn] = struct{}{}
	case http.StateClosed:
		delete(server.connections, conn)
	}
}

func (server *Server) newHandler(ca *certificateAuthority, requestHooks []RequestHook, responseHooks []ResponseHook) *goproxy.ProxyHttpServer {
	handler := goproxy.NewProxyHttpServer()
	handler.Logger = proxyLogger{}
	handler.Tr = server.transport
	// goproxy's default CONNECT dialer reads HTTPS_PROXY from the environment.
	// Every CONNECT is intercepted below, so no dialer is needed; clear them
	// rather than leave an environment-driven path in place.
	handler.ConnectDial = nil
	handler.ConnectDialWithReq = nil
	// Forward the client's Accept-Encoding and leave bodies untouched, so the
	// package manager receives exactly what the registry sent.
	handler.KeepAcceptEncoding = true

	// Intercept every HTTPS tunnel with a certificate from the per-run CA, so
	// the requests inside are visible to the proxy.
	mitm := &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm,
		TLSConfig: func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
			return ca.serverTLSConfig(host), nil
		},
	}
	handler.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitm, host
	})

	handler.OnRequest().DoFunc(func(request *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		request = request.WithContext(server.requestContext(request.Context()))
		observed := Request{Method: request.Method, URL: *request.URL}
		if err := runRequestHooks(request.Context(), requestHooks, observed); err != nil {
			slog.Debug("proxy rejected request", "method", request.Method, "url", redactURL(request.URL), "reason", err)
			return request, goproxy.NewResponse(request, goproxy.ContentTypeText, http.StatusForbidden, err.Error()+"\n")
		}
		// Response hooks run on upstream responses only, so responses generated
		// above never reach them.
		proxyCtx.RoundTripper = goproxy.RoundTripperFunc(func(request *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			response, err := server.transport.RoundTrip(request)
			if err != nil {
				return nil, err
			}
			for _, hook := range responseHooks {
				hook(request.Context(), Response{Request: observed, StatusCode: response.StatusCode})
			}
			return response, nil
		})
		return request, nil
	})

	return handler
}

// requestContext returns a context for one proxied request that is canceled
// when either the client's own request context ends or the proxy closes.
// goproxy only cancels requests inside intercepted HTTPS tunnels once the
// exchange ends, so a client that drops such a tunnel is noticed when the
// response is written back.
func (server *Server) requestContext(clientCtx context.Context) context.Context {
	ctx, cancel := context.WithCancel(clientCtx)
	stop := context.AfterFunc(server.ctx, cancel)
	// Unregister from the proxy's context once the request is done.
	context.AfterFunc(ctx, func() { stop() })
	return ctx
}

func runRequestHooks(ctx context.Context, hooks []RequestHook, request Request) error {
	for _, hook := range hooks {
		if err := hook(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

func newUpstreamTransport(options Options) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Route through the supplied upstream proxy only; never consult the
	// process environment.
	proxyFunc := options.Upstream.ProxyFunc()
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		return proxyFunc(request.URL)
	}
	// Intercepted HTTPS is re-encrypted toward the registry, so the proxy, not
	// the package manager, now verifies the registry's certificate.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.upstreamRootCAs}
	transport.DisableCompression = true
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	if options.dialContext != nil {
		transport.DialContext = options.dialContext
	}
	return transport
}

// redactURL renders u for logs without user information or query parameters,
// either of which may carry registry credentials.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	redacted := *u
	redacted.User = nil
	redacted.RawQuery = ""
	redacted.ForceQuery = false
	return redacted.String()
}

// proxyLogger routes goproxy diagnostics to debug logs. Only the message
// template is logged: goproxy interpolates raw request data, such as URLs and
// header parse errors quoting whole headers, which can carry credentials.
type proxyLogger struct{}

func (proxyLogger) Printf(format string, _ ...any) {
	slog.Debug("package manager proxy diagnostic", "detail", format)
}
