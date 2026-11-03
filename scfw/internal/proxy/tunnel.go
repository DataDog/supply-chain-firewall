// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// serveTunnel uses net/http for intercepted requests so its background reader
// detects disconnected clients while hooks wait on upstream metadata. A manual
// read-request/write-response loop cannot detect EOF during that wait.
func (server *Server) serveTunnel(client net.Conn, host string, ca *certificateAuthority, handler http.Handler) {
	defer client.Close() //nolint:errcheck
	defer server.trackConnection(client, http.StateClosed)
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	// Preserve support for both TLS and plain HTTP inside a CONNECT tunnel.
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(client)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})
	var connection net.Conn = &bufferedTunnelConn{Conn: client, reader: reader}
	scheme := "http"
	if first[0] == 22 { // TLS handshake record.
		connection = tls.Server(connection, ca.serverTLSConfig(host))
		scheme = "https"
	}
	listener := &tunnelListener{connection: connection, closed: make(chan struct{})}
	stop := context.AfterFunc(server.ctx, func() { _ = listener.Close() })
	defer stop()
	tunnel := &http.Server{
		BaseContext:       func(net.Listener) context.Context { return server.ctx },
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          server.httpServer.ErrorLog,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				_ = listener.Close()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			request.URL.Scheme = scheme
			request.URL.Host = request.Host
			if request.URL.Host == "" {
				request.URL.Host = host
			}
			writer := &tunnelResponseWriter{ResponseWriter: w}
			defer func() {
				// net/http stops tracking hijacked connections. Keep the tunnel
				// alive during the relay, then release it when that relay ends.
				if writer.hijacked {
					_ = listener.Close()
				}
			}()
			handler.ServeHTTP(writer, request)
		}),
	}
	_ = tunnel.Serve(listener)
}

type bufferedTunnelConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedTunnelConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}

// tunnelListener hands one already-accepted connection to net/http and stays
// alive until that connection closes or the command's proxy shuts down.
type tunnelListener struct {
	connection net.Conn
	accepted   bool
	closed     chan struct{}
	closeOnce  sync.Once
}

func (listener *tunnelListener) Accept() (net.Conn, error) {
	if !listener.accepted {
		listener.accepted = true
		return listener.connection, nil
	}
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *tunnelListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.closed) })
	return nil
}

func (listener *tunnelListener) Addr() net.Addr { return listener.connection.LocalAddr() }

// Flush each forwarded chunk to retain ordinary artifact streaming through the
// HTTP server. Inspected bodies reach this writer only after their hooks finish.
type tunnelResponseWriter struct {
	http.ResponseWriter
	hijacked bool
}

func (writer tunnelResponseWriter) Write(body []byte) (int, error) {
	written, err := writer.ResponseWriter.Write(body)
	if err == nil {
		err = http.NewResponseController(writer.ResponseWriter).Flush()
	}
	return written, err
}

func (writer tunnelResponseWriter) Flush() {
	_ = http.NewResponseController(writer.ResponseWriter).Flush()
}

func (writer *tunnelResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffer, err := http.NewResponseController(writer.ResponseWriter).Hijack()
	if err == nil {
		writer.hijacked = true
	}
	return connection, buffer, err
}
