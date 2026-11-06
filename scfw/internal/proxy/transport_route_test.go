// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOutboundRoutesIsolateSameHostTLS(t *testing.T) {
	ca, err := newCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := ca.leafCertificate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var clients atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private" {
			if len(r.TLS.PeerCertificates) == 0 {
				t.Error("source client certificate missing")
			}
			clients.Add(1)
		} else if len(r.TLS.PeerCertificates) != 0 {
			t.Error("client certificate leaked across source paths")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	origin.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*certificate}, ClientAuth: tls.RequestClientCert}
	origin.StartTLS()
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	private := &OutboundRoute{TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{*certificate}}}
	public := &OutboundRoute{TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	transport := NewTransport(Options{RouteForRequest: func(request Request) (*OutboundRoute, error) {
		if request.URL.Path == "/private" {
			return private, nil
		}
		return public, nil
	}})
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, path := range []string{"/private", "/public", "/private", "/public"} {
		response, err := client.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	var workers sync.WaitGroup
	errors := make(chan error, 20)
	for index := 0; index < 20; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			path := "/public"
			if index%2 == 0 {
				path = "/private"
			}
			response, err := client.Get(origin.URL + path)
			if err != nil {
				errors <- err
				return
			}
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if err != nil {
				errors <- err
			}
		}(index)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	if clients.Load() != 12 {
		t.Fatal("private source not exercised")
	}
	// The exception must not reuse a connection that bypassed verification.
	public.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}
	other := &OutboundRoute{TLS: public.TLS}
	transport.routeForRequest = func(Request) (*OutboundRoute, error) { return other, nil }
	if response, err := client.Get(origin.URL + "/untrusted"); err == nil {
		_ = response.Body.Close()
		t.Fatal("destination trust leaked across routes")
	}
}

func TestOutboundHTTPSProxyHasIndependentTLS(t *testing.T) {
	ca, err := newCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := ca.leafCertificate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("destination client certificate missing")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	origin.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*certificate}, ClientAuth: tls.RequireAnyClientCert}
	origin.StartTLS()
	defer origin.Close()
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", 400)
			return
		}
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("destination certificate leaked to HTTPS proxy")
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")) {
			t.Error("proxy credentials missing")
		}
		connections.Add(1)
		remote, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		local, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = remote.Close()
			return
		}
		defer func() { _ = remote.Close(); _ = local.Close() }()
		_, _ = fmt.Fprint(buffer, "HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buffer.Flush()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(remote, buffer); _ = remote.Close(); close(done) }()
		_, _ = io.Copy(local, remote)
		_ = local.Close()
		<-done
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	upstream.StartTLS()
	defer upstream.Close()
	proxyRoots := x509.NewCertPool()
	proxyRoots.AddCert(upstream.Certificate())
	address, _ := url.Parse(strings.Replace(upstream.URL, "://", "://user:secret@", 1))
	route := &OutboundRoute{ProxyURL: address, TLS: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, Certificates: []tls.Certificate{*certificate}}, ProxyTLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: proxyRoots}}
	transport := NewTransport(Options{RouteForRequest: func(Request) (*OutboundRoute, error) { return route, nil }})
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if connections.Load() != 1 {
		t.Fatal("HTTPS proxy not used")
	}
	// An invalid proxy CA must fail even when destination verification is disabled.
	bad := *route
	bad.ProxyTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}
	transport.routeForRequest = func(Request) (*OutboundRoute, error) { return &bad, nil }
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	if response, err := transport.RoundTrip(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("destination trust exception disabled HTTPS proxy verification")
	}
}
