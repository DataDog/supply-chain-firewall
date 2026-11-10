// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package proxy provides a short-lived, loopback-only HTTP/HTTPS interception
// proxy that lets SCFW observe, and reject, a package manager's registry traffic.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	Header http.Header
	// ClientIdentity identifies policy through an isolated invocation listener
	// or an invocation-only TLS certificate, without URL-wide trust.
	ClientIdentity string
}

// Response is a copy of an upstream response. Body is populated only for a
// requested body hook; mutating this snapshot never changes the forwarded bytes.
type Response struct {
	Request    Request
	StatusCode int
	Header     http.Header
	Body       []byte
}

// RequestHook observes a request before it is sent upstream. ctx is canceled
// when the command is canceled or the proxy closes. Returning a non-nil error
// rejects the request with HTTP 403 Forbidden and the error text
// as body, without contacting upstream. A returned response hook belongs only
// to this request and runs only if its upstream response arrives.
type RequestHook func(ctx context.Context, request Request) (ResponseHook, error)

// ResponseHook observes an upstream response before it is streamed back to the
// client. ctx is canceled when the command is canceled or the proxy closes.
// Returning nil leaves the body streaming; returning a body hook asks
// the proxy to buffer and inspect it before forwarding any response bytes.
// ErrResponseRejected produces HTTP 403; other errors produce HTTP 502.
type ResponseHook func(ctx context.Context, response Response) (*ResponseBodyHook, error)

// ErrResponseRejected lets a response hook reject a completed upstream response
// with HTTP 403. The wrapped error is never exposed to the client or logs.
var ErrResponseRejected = errors.New("upstream response rejected")

// ResponseBodyHook processes a complete, bounded copy of a response body.
// MaxBytes must be positive and exactly one handler must be set. Handle uses an
// in-memory copy; HandleFile opts into temporary-file buffering and receives a
// read-only view valid for that call. Inspection finishes before forwarding.
// ErrResponseRejected produces HTTP 403; other failures produce HTTP 502.
type ResponseBodyHook struct {
	MaxBytes   int64
	Handle     func(context.Context, Response) error
	HandleFile func(context.Context, Response, *io.SectionReader) error
}

// Options configures a proxy.
type Options struct {
	// ClientIdentity identifies this listener when a request presents no TLS
	// identity. Run assigns identities to additional client listeners.
	ClientIdentity string
	// AdditionalClients supplies isolated proxy/TLS settings for other HTTP
	// clients launched by the same command. Run owns their complete lifecycle.
	// Profiles are not recursive; all clients share the invocation's hooks.
	AdditionalClients map[string]Options
	// Upstream is the proxy configuration that was in effect before SCFW, as
	// supplied by the package manager integration. Outbound requests honor it so
	// corporate proxies keep working. The zero value connects directly; the
	// process environment is never consulted, which prevents the proxy from
	// routing to itself through the variables it sets for its child.
	Upstream httpproxy.Config

	// ProxyForURL overrides flattened proxy settings when the caller has
	// request-specific proxy precedence, such as an explicit fallback proxy.
	ProxyForURL func(*url.URL) (*url.URL, error)

	// UpstreamTLS preserves the caller's registry CA and trust configuration.
	UpstreamTLS *tls.Config

	// RouteForRequest selects immutable, invocation-scoped outbound settings.
	// Returning nil uses the default transport. Adapters own configuration
	// discovery and selection; each returned route has its own connection pool.
	RouteForRequest func(Request) (*OutboundRoute, error)

	// TrustedHosts skips registry certificate verification only for matching
	// hosts, optionally constrained to a port.
	TrustedHosts []string

	// TrustURL applies a caller-owned, invocation-scoped trust exception.
	TrustURL func(*url.URL) bool

	// RequestHooks run, in order, for each request. The first rejection wins.
	RequestHooks []RequestHook

	// upstreamRootCAs and dialContext let tests reach local upstream servers;
	// nil means the system roots and the default dialer.
	upstreamRootCAs *x509.CertPool
	dialContext     func(ctx context.Context, network, address string) (net.Conn, error)
}

// ClientConfig is what a package manager needs to route its traffic through
// the proxy and trust its interception certificates.
type ClientConfig struct {
	AdditionalClients map[string]ClientConfig
	// URL is the proxy URL, used for both HTTP and HTTPS traffic.
	URL string

	// CACertificatePath is a PEM file holding the per-run CA certificate.
	CACertificatePath string
	// IdentityCertificate creates a private, invocation-only PEM certificate/key
	// for a client which carries TLS policy across redirects. Its files are
	// removed with the proxy. Nil configurations do not support identities.
	IdentityCertificate func(identity string) (string, error)
}

// Server is a running proxy with its own per-run certificate authority.
type Server struct {
	listener     net.Listener
	httpServer   *http.Server
	transport    *Transport
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
		transport:    NewTransport(options),
		clientConfig: ClientConfig{URL: proxyURL, CACertificatePath: certificatePath},
		served:       make(chan error, 1),
		ctx:          serverCtx,
		cancel:       cancel,
		connections:  make(map[net.Conn]struct{}),
	}
	server.clientConfig.IdentityCertificate = func(identity string) (string, error) {
		return ca.identityCertificate(certificateDir, identity)
	}
	server.httpServer = &http.Server{
		Handler:           server.newHandler(ca, options.RequestHooks, options.ClientIdentity),
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

func (server *Server) newHandler(
	ca *certificateAuthority,
	requestHooks []RequestHook,
	listenerIdentity string,
) *goproxy.ProxyHttpServer {
	handler := goproxy.NewProxyHttpServer()
	handler.Logger = proxyLogger{}
	handler.Tr = server.transport.secure
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
		TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			config := ca.serverTLSConfig(host)
			ca.clientIdentityTLS(config, func(identity string) { ctx.UserData = identity })
			return config, nil
		},
	}
	handler.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitm, host
	})

	handler.OnRequest().DoFunc(func(request *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		request = request.WithContext(server.requestContext(request.Context()))
		identity, _ := proxyCtx.UserData.(string)
		if identity == "" {
			identity = listenerIdentity
		}
		observed := Request{Method: request.Method, URL: *request.URL, Header: request.Header.Clone(), ClientIdentity: identity}
		responseHooks, err := runRequestHooks(request.Context(), requestHooks, observed)
		if err != nil {
			slog.Debug("proxy rejected request", "method", request.Method, "url", redactURL(request.URL), "reason", err)
			return request, goproxy.NewResponse(request, goproxy.ContentTypeText, http.StatusForbidden, err.Error()+"\n")
		}
		// Response hooks run on upstream responses only, so responses generated
		// above never reach them.
		proxyCtx.RoundTripper = goproxy.RoundTripperFunc(func(request *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			forwarded := request.WithContext(context.WithValue(request.Context(), clientIdentityContextKey{}, identity))
			response, err := server.transport.RoundTrip(forwarded)
			if err != nil {
				return nil, err
			}
			if err := runResponseHooks(request.Context(), observed, response, responseHooks, filepath.Dir(server.clientConfig.CACertificatePath)); err != nil {
				_ = response.Body.Close()
				// Hook and transport errors may contain credentials or body data.
				// Do not expose their contents in the response or diagnostics.
				slog.Debug("proxy could not inspect upstream response", "url", redactURL(request.URL))
				if errors.Is(err, ErrResponseRejected) {
					return goproxy.NewResponse(request, goproxy.ContentTypeText, http.StatusForbidden,
						"supply chain firewall rejected upstream response\n"), nil
				}
				return goproxy.NewResponse(request, goproxy.ContentTypeText, http.StatusBadGateway,
					"supply chain firewall could not inspect upstream response\n"), nil
			}
			// ErrAbortHandler must reach net/http's recovery handler. CONNECT
			// requests use goproxy's own response writer and error handling.
			if request.Context().Value(http.ServerContextKey) != nil && response.StatusCode != http.StatusSwitchingProtocols {
				response.Body = &streamingResponseBody{ReadCloser: response.Body}
			}
			return response, nil
		})
		return request, nil
	})

	return handler
}

func runResponseHooks(ctx context.Context, request Request, response *http.Response, hooks []ResponseHook, temporaryDir string) error {
	var bodyHooks []*ResponseBodyHook
	var limit int64
	useFile := false
	for _, hook := range hooks {
		bodyHook, err := hook(ctx, responseSnapshot(request, response, nil))
		if err != nil {
			return err
		}
		if bodyHook == nil {
			continue
		}
		if bodyHook.MaxBytes <= 0 || bodyHook.MaxBytes == math.MaxInt64 || (bodyHook.Handle == nil) == (bodyHook.HandleFile == nil) {
			return errors.New("invalid proxy response body hook")
		}
		if limit == 0 || bodyHook.MaxBytes < limit {
			limit = bodyHook.MaxBytes
		}
		bodyHooks = append(bodyHooks, bodyHook)
		useFile = useFile || bodyHook.HandleFile != nil
	}
	if len(bodyHooks) == 0 {
		return ctx.Err()
	}
	length := response.ContentLength
	if request.Method == http.MethodHead || response.StatusCode == http.StatusNoContent ||
		response.StatusCode == http.StatusNotModified || response.StatusCode < http.StatusOK {
		length = 0
	}
	if length > limit {
		slog.Warn("proxy response exceeds inspection limit", "url", redactURL(&request.URL), "limit_bytes", limit)
		return errors.New("upstream response exceeds inspection limit")
	}
	if useFile {
		return inspectResponseFile(ctx, request, response, bodyHooks, temporaryDir, length, limit)
	}
	readLimit := limit + 1
	if length >= 0 {
		// A known-length HTTP/2 body can be complete before END_STREAM arrives.
		readLimit = length
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, readLimit))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		slog.Warn("proxy response exceeds inspection limit", "url", redactURL(&request.URL), "limit_bytes", limit)
		return errors.New("upstream response exceeds inspection limit")
	}
	if length >= 0 && int64(len(body)) != length {
		return io.ErrUnexpectedEOF
	}
	for _, hook := range bodyHooks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := hook.Handle(ctx, responseSnapshot(request, response, body)); err != nil {
			return err
		}
	}
	// Retain the upstream reader after the replayed bytes so its EOF/trailers
	// and connection cleanup still follow the ordinary response lifecycle.
	response.Body = &bufferedResponseBody{
		Reader: io.MultiReader(bytes.NewReader(body), response.Body),
		Closer: response.Body,
	}
	return ctx.Err()
}

func responseSnapshot(request Request, response *http.Response, body []byte) Response {
	request.Header = request.Header.Clone()
	return Response{Request: request, StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: bytes.Clone(body)}
}

type bufferedResponseBody struct {
	io.Reader
	io.Closer
}

// For plain HTTP, goproxy logs copy errors and returns normally, which lets
// net/http finish a truncated chunked response as though it succeeded. Abort the
// downstream response on read failure instead. Upgraded bodies retain their ReadWriter.
type streamingResponseBody struct{ io.ReadCloser }

func (body *streamingResponseBody) Read(buffer []byte) (int, error) {
	read, err := body.ReadCloser.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		panic(http.ErrAbortHandler)
	}
	return read, err
}

// requestContext returns a context for one proxied request that is canceled
// when either the client's own request context ends or the proxy closes.
// Inside CONNECT tunnels, goproxy ends the client context after the exchange;
// the proxy context still cancels upstream work when the command stops.
func (server *Server) requestContext(clientCtx context.Context) context.Context {
	ctx, cancel := context.WithCancel(clientCtx)
	stop := context.AfterFunc(server.ctx, cancel)
	// Unregister from the proxy's context once the request is done.
	context.AfterFunc(ctx, func() { stop() })
	return ctx
}

func runRequestHooks(ctx context.Context, hooks []RequestHook, request Request) ([]ResponseHook, error) {
	var responseHooks []ResponseHook
	for _, hook := range hooks {
		snapshot := request
		snapshot.Header = request.Header.Clone()
		responseHook, err := hook(ctx, snapshot)
		if err != nil {
			return nil, err
		}
		if responseHook != nil {
			responseHooks = append(responseHooks, responseHook)
		}
	}
	return responseHooks, nil
}

func newUpstreamTransport(options Options) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Route through the supplied upstream proxy only; never consult the
	// process environment.
	proxyFunc := options.Upstream.ProxyFunc()
	if options.ProxyForURL != nil {
		proxyFunc = options.ProxyForURL
	}
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		return proxyFunc(request.URL)
	}
	// Intercepted HTTPS is re-encrypted toward the registry, so the proxy, not
	// the package manager, now verifies the registry's certificate.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.upstreamRootCAs}
	if options.UpstreamTLS != nil {
		transport.TLSClientConfig = options.UpstreamTLS.Clone()
	}
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

// Transport routes outbound traffic with invocation-scoped proxy and TLS trust.
// Separate connection pools keep trusted-host exceptions from leaking to other ports.
type Transport struct {
	secure          *http.Transport
	trusted         *http.Transport
	hosts           []string
	trustURL        func(*url.URL) bool
	routeForRequest func(Request) (*OutboundRoute, error)
	routesMutex     sync.Mutex
	routes          map[*OutboundRoute]*http.Transport
	defaultRoutes   map[defaultRouteKey]*OutboundRoute
}

// NewTransport creates an outbound transport using only the supplied settings.
func NewTransport(options Options) *Transport {
	secure := newUpstreamTransport(options)
	trusted := secure.Clone()
	trusted.TLSClientConfig = secure.TLSClientConfig.Clone()
	trusted.TLSClientConfig.InsecureSkipVerify = true // Only selected by an explicit host/port match.
	return &Transport{secure: secure, trusted: trusted, hosts: options.TrustedHosts, trustURL: options.TrustURL,
		routeForRequest: options.RouteForRequest, routes: make(map[*OutboundRoute]*http.Transport), defaultRoutes: make(map[defaultRouteKey]*OutboundRoute)}
}

func (transport *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.routeForRequest != nil {
		route, err := transport.routeForRequest(Request{Method: request.Method, URL: *request.URL, Header: request.Header.Clone(), ClientIdentity: clientIdentity(request.Context())})
		if err != nil {
			return nil, errors.New("could not resolve outbound request settings")
		}
		if route != nil {
			return transport.routeTransport(route).RoundTrip(request)
		}
	}
	if transport.trustURL != nil && transport.trustURL(request.URL) {
		return transport.roundTripDefault(request, transport.trusted)
	}
	for _, trusted := range transport.hosts {
		host, port, err := net.SplitHostPort(trusted)
		if err != nil {
			// Bracketed IPv6 hosts can omit the port. Parse an explicit empty
			// port to remove the brackets without changing bare IPv6 hosts.
			host, port, err = net.SplitHostPort(trusted + ":")
			if err != nil {
				host, port = trusted, ""
			}
		}
		targetPort := request.URL.Port()
		if targetPort == "" {
			if request.URL.Scheme == "https" {
				targetPort = "443"
			} else {
				targetPort = "80"
			}
		}
		if (host == "*" || strings.EqualFold(host, request.URL.Hostname())) && (port == "" || port == targetPort) {
			return transport.roundTripDefault(request, transport.trusted)
		}
	}
	return transport.roundTripDefault(request, transport.secure)
}

// CloseIdleConnections releases idle connections in both trust pools.
func (transport *Transport) CloseIdleConnections() {
	transport.secure.CloseIdleConnections()
	transport.trusted.CloseIdleConnections()
	transport.routesMutex.Lock()
	defer transport.routesMutex.Unlock()
	for _, route := range transport.routes {
		route.CloseIdleConnections()
	}
}
