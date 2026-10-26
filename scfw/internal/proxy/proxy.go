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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
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

// Options configures a proxy.
type Options struct {
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

	closeOnce sync.Once
	closeErr  error
}

// Start creates a per-run CA, writes its public certificate to a private
// temporary directory, and starts a proxy on a loopback ephemeral port. The
// caller must call Close once the proxied process has exited.
func Start(options Options) (*Server, error) {
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

	server := &Server{
		listener:     listener,
		transport:    newUpstreamTransport(options),
		clientConfig: ClientConfig{URL: proxyURL, CACertificatePath: certificatePath},
		served:       make(chan error, 1),
	}
	server.httpServer = &http.Server{
		Handler:           server.newHandler(ca),
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

// Close stops the proxy and removes its temporary certificate material. Close
// is idempotent.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
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

func (server *Server) newHandler(ca *certificateAuthority) *goproxy.ProxyHttpServer {
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

	return handler
}

func newUpstreamTransport(options Options) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Connect directly; never consult the process environment for a proxy.
	transport.Proxy = nil
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

// proxyLogger routes goproxy diagnostics to debug logs. Only the message
// template is logged: goproxy interpolates raw request data, such as URLs and
// header parse errors quoting whole headers, which can carry credentials.
type proxyLogger struct{}

func (proxyLogger) Printf(format string, _ ...any) {
	slog.Debug("package manager proxy diagnostic", "detail", format)
}
