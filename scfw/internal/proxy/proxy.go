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

	// shutdownTimeout bounds how long Close waits for in-flight exchanges.
	shutdownTimeout = 2 * time.Second

	// maxIdleConnsPerHost keeps upstream connections for reuse: package
	// managers fetch many artifacts concurrently from one or two registries,
	// and the default of 2 would reconnect after every burst.
	maxIdleConnsPerHost = 32
)

// RequestHook observes a request before it is sent upstream. ctx is canceled
// when the proxy closes. Returning a non-nil error rejects the request with
// HTTP 403 Forbidden and the error text as body, without contacting upstream.
// Hooks must not consume the request body.
type RequestHook func(ctx context.Context, request *http.Request) error

// ResponseHook observes an upstream response before it is streamed back to the
// client. ctx is canceled when the proxy closes. The body is forwarded as-is,
// including any Content-Encoding. A hook that needs the body may replace
// response.Body with a reader that wraps the original, but must preserve
// streaming and never buffer whole artifacts.
type ResponseHook func(ctx context.Context, response *http.Response)

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

	// ctx is given to hooks. It is canceled when the caller's context is
	// canceled or Close is called.
	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

// Start creates a per-run CA, writes its public certificate to a private
// temporary directory, and starts a proxy on a loopback ephemeral port. The
// caller must call Close once the proxied process has exited. Canceling ctx
// cancels the context given to hooks, but does not stop the server.
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
	}
	server.httpServer = &http.Server{
		Handler:           server.newHandler(ca, options.RequestHooks, options.ResponseHooks),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
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
// cancels the context given to hooks. Close is idempotent.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		server.cancel()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		shutdownErr := server.httpServer.Shutdown(shutdownCtx)
		server.transport.CloseIdleConnections()
		serveErr := <-server.served
		removeErr := os.RemoveAll(filepath.Dir(server.clientConfig.CACertificatePath))

		var errs []error
		if shutdownErr != nil && !errors.Is(shutdownErr, context.DeadlineExceeded) {
			errs = append(errs, fmt.Errorf("shut down proxy: %w", shutdownErr))
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
		if err := runRequestHooks(server.ctx, requestHooks, request); err != nil {
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
				hook(server.ctx, response)
			}
			return response, nil
		})
		return request, nil
	})

	return handler
}

func runRequestHooks(ctx context.Context, hooks []RequestHook, request *http.Request) error {
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
