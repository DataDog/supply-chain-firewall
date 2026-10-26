// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package proxy provides a short-lived, loopback-only HTTP/HTTPS interception
// proxy that lets SCFW observe, and reject, a package manager's registry traffic.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	// listenAddress restricts the proxy to loopback on an OS-assigned port.
	listenAddress = "127.0.0.1:0"

	// shutdownTimeout bounds how long Close waits for in-flight exchanges.
	shutdownTimeout = 2 * time.Second

	// maxIdleConnsPerHost keeps upstream connections for reuse: package
	// managers fetch many artifacts concurrently from one or two registries,
	// and the default of 2 would reconnect after every burst.
	maxIdleConnsPerHost = 32
)

// Options configures a proxy.
type Options struct{}

// ClientConfig is what a package manager needs to route its traffic through
// the proxy.
type ClientConfig struct {
	// URL is the proxy URL, used for both HTTP and HTTPS traffic.
	URL string
}

// Server is a running proxy.
type Server struct {
	listener     net.Listener
	httpServer   *http.Server
	transport    *http.Transport
	clientConfig ClientConfig
	served       chan error

	closeOnce sync.Once
	closeErr  error
}

// Start starts a proxy on a loopback ephemeral port. The caller must call
// Close once the proxied process has exited.
func Start(_ Options) (*Server, error) {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for proxy connections: %w", err)
	}
	proxyURL := "http://" + listener.Addr().String()

	server := &Server{
		listener:     listener,
		transport:    newUpstreamTransport(),
		clientConfig: ClientConfig{URL: proxyURL},
		served:       make(chan error, 1),
	}
	server.httpServer = &http.Server{
		Handler:           server.newHandler(),
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

// Close stops the proxy. Close is idempotent.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		shutdownErr := server.httpServer.Shutdown(shutdownCtx)
		server.transport.CloseIdleConnections()
		serveErr := <-server.served

		var errs []error
		if shutdownErr != nil && !errors.Is(shutdownErr, context.DeadlineExceeded) {
			errs = append(errs, fmt.Errorf("shut down proxy: %w", shutdownErr))
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("serve proxy: %w", serveErr))
		}
		server.closeErr = errors.Join(errs...)
		slog.Debug("stopped package manager proxy")
	})
	return server.closeErr
}

func (server *Server) newHandler() *goproxy.ProxyHttpServer {
	handler := goproxy.NewProxyHttpServer()
	handler.Logger = proxyLogger{}
	handler.Tr = server.transport
	// goproxy's default CONNECT dialer reads HTTPS_PROXY from the environment.
	// Clearing both dialers makes tunnels dial through transport instead.
	handler.ConnectDial = nil
	handler.ConnectDialWithReq = nil
	// Forward the client's Accept-Encoding and leave bodies untouched, so the
	// package manager receives exactly what the registry sent.
	handler.KeepAcceptEncoding = true
	return handler
}

func newUpstreamTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Connect directly; never consult the process environment for a proxy.
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return transport
}

// proxyLogger routes goproxy diagnostics to debug logs. Only the message
// template is logged: goproxy interpolates raw request data, such as URLs and
// header parse errors quoting whole headers, which can carry credentials.
type proxyLogger struct{}

func (proxyLogger) Printf(format string, _ ...any) {
	slog.Debug("package manager proxy diagnostic", "detail", format)
}
