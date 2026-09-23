// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package proxy provides a short-lived, loopback-only HTTPS interception proxy.
package proxy

import (
	"context"
	"crypto/tls"
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

const shutdownTimeout = 5 * time.Second

// Request describes a request observed by the proxy.
type Request struct {
	Method string
	URL    string
}

// Response describes a response observed by the proxy.
type Response struct {
	Request    Request
	StatusCode int
	Status     string
}

// Options configures request handling, response observation, and the outbound transport.
type Options struct {
	// OnRequest is called before a GET request is sent upstream. Returning an
	// error rejects the request with an HTTP 403 response.
	OnRequest  func(Request) error
	OnResponse func(Response)
	Transport  *http.Transport
}

// Server is a running HTTPS interception proxy with an invocation-specific CA.
type Server struct {
	listener       net.Listener
	httpServer     *http.Server
	certificateDir string
	certificate    string
	done           chan error
	closeOnce      sync.Once
	closeErr       error
}

// Start creates an ephemeral CA and starts a proxy on a random loopback port.
func Start(options Options) (*Server, error) {
	ca, certificatePEM, err := newCertificateAuthority(time.Now())
	if err != nil {
		return nil, fmt.Errorf("create ephemeral certificate authority: %w", err)
	}

	certificateDir, err := os.MkdirTemp("", "scfw-proxy-")
	if err != nil {
		return nil, fmt.Errorf("create certificate directory: %w", err)
	}
	certificatePath := filepath.Join(certificateDir, "ca.pem")
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		_ = os.RemoveAll(certificateDir)
		return nil, fmt.Errorf("write certificate: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.RemoveAll(certificateDir)
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}

	handler := newHandler(ca, options)
	server := &Server{
		listener:       listener,
		httpServer:     &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second},
		certificateDir: certificateDir,
		certificate:    certificatePath,
		done:           make(chan error, 1),
	}
	go func() {
		server.done <- server.httpServer.Serve(listener)
		close(server.done)
	}()

	return server, nil
}

func newHandler(ca tls.Certificate, options Options) *goproxy.ProxyHttpServer {
	handler := goproxy.NewProxyHttpServer()
	handler.Logger = proxyLogger{}
	handler.ConnectDial = nil
	if options.Transport != nil {
		handler.Tr = options.Transport
	} else {
		handler.Tr = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}

	mitm := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}
	handler.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitm, host
	})

	if options.OnRequest != nil {
		handler.OnRequest().DoFunc(func(request *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if request.Method != http.MethodGet {
				return request, nil
			}
			if err := options.OnRequest(observedRequest(request)); err != nil {
				return request, goproxy.NewResponse(request, "text/plain", http.StatusForbidden, err.Error()+"\n")
			}
			return request, nil
		})
	}
	if options.OnResponse != nil {
		handler.OnResponse().DoFunc(func(response *http.Response, proxyContext *goproxy.ProxyCtx) *http.Response {
			if response != nil && proxyContext.Req != nil && proxyContext.Req.Method == http.MethodGet {
				options.OnResponse(Response{
					Request:    observedRequest(proxyContext.Req),
					StatusCode: response.StatusCode,
					Status:     response.Status,
				})
			}
			return response
		})
	}
	return handler
}

func observedRequest(request *http.Request) Request {
	if request == nil {
		return Request{}
	}
	if request.URL == nil {
		return Request{Method: request.Method}
	}
	requestURL := *request.URL
	requestURL.User = nil
	return Request{Method: request.Method, URL: requestURL.String()}
}

// URL returns the HTTP URL clients use for both HTTP and HTTPS proxying.
func (server *Server) URL() string {
	return "http://" + server.listener.Addr().String()
}

// CertificatePath returns the PEM file containing the ephemeral CA certificate.
func (server *Server) CertificatePath() string {
	return server.certificate
}

// Close stops the proxy and removes its ephemeral certificate.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		shutdownErr := server.httpServer.Shutdown(ctx)
		serveErr := <-server.done
		removeErr := os.RemoveAll(server.certificateDir)

		switch {
		case shutdownErr != nil:
			server.closeErr = fmt.Errorf("shut down proxy: %w", shutdownErr)
		case serveErr != nil && serveErr != http.ErrServerClosed:
			server.closeErr = fmt.Errorf("serve proxy: %w", serveErr)
		case removeErr != nil:
			server.closeErr = fmt.Errorf("remove certificate directory: %w", removeErr)
		}
	})
	return server.closeErr
}

type proxyLogger struct{}

func (proxyLogger) Printf(format string, values ...any) {
	slog.Warn("HTTPS proxy error", "detail", fmt.Sprintf(format, values...))
}
