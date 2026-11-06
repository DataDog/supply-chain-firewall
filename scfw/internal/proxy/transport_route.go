// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
)

// OutboundRoute separates destination TLS from HTTPS-proxy TLS. A nil proxy
// connects directly; nil TLS settings use system trust. Treat routes and their
// TLS configurations as immutable after handing them to a Transport.
type OutboundRoute struct {
	ProxyURL *url.URL
	TLS      *tls.Config
	ProxyTLS *tls.Config
}

func (transport *Transport) routeTransport(route *OutboundRoute) *http.Transport {
	transport.routesMutex.Lock()
	defer transport.routesMutex.Unlock()
	if existing := transport.routes[route]; existing != nil {
		return existing
	}
	configured := newUpstreamTransport(Options{UpstreamTLS: route.TLS})
	configured.DialContext = transport.secure.DialContext
	configured.Proxy = http.ProxyURL(route.ProxyURL)
	if route.ProxyURL != nil && route.ProxyURL.Scheme == "https" {
		proxyTLS := &tls.Config{MinVersion: tls.VersionTLS12}
		if route.ProxyTLS != nil {
			proxyTLS = route.ProxyTLS.Clone()
		}
		proxyTLS.ServerName = route.ProxyURL.Hostname()
		// net/http speaks HTTP/1.1 CONNECT on this connection. Destination
		// client certificates and verification exceptions must never reach it.
		proxyTLS.NextProtos = []string{"http/1.1"}
		configured.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := configured.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			secured := tls.Client(connection, proxyTLS)
			if err := secured.HandshakeContext(ctx); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return secured, nil
		}
	}
	transport.routes[route] = configured
	return configured
}
