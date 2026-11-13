// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
)

func TestClientIdentityIsAuthenticatedScopedAndCleaned(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("invocation identity was forwarded upstream")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	var identified, anonymous atomic.Int32
	route := &OutboundRoute{TLS: origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	server, err := Start(context.Background(), Options{RouteForRequest: func(request Request) (*OutboundRoute, error) {
		if request.ClientIdentity == "source" {
			identified.Add(1)
		} else if request.ClientIdentity == "" {
			anonymous.Add(1)
		} else {
			t.Error("unrecognized TLS identity")
		}
		return route, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	config := server.ClientConfig()
	identity, err := config.IdentityCertificate("source")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(identity)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("identity permissions: %v / %v", info, err)
	}
	other, err := Start(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	foreign, err := other.ClientConfig().IdentityCertificate("source")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	address, _ := url.Parse(config.URL)
	for _, path := range []string{identity, "", foreign, ""} {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		if path != "" {
			certificate, err := tls.LoadX509KeyPair(path, path)
			if err != nil {
				t.Fatal(err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
		transport := &http.Transport{Proxy: http.ProxyURL(address), TLSClientConfig: tlsConfig}
		request, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
		request.Header.Set("X-SCFW-Client-Identity", "source")
		response, err := (&http.Client{Transport: transport}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status: %s", response.Status)
		}
	}
	if identified.Load() != 1 || anonymous.Load() != 3 {
		t.Fatalf("identity leaked across requests: %d/%d", identified.Load(), anonymous.Load())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(identity); !os.IsNotExist(err) {
		t.Fatal("client identity survived cleanup")
	}
}

func TestIsolatedListenerIdentityReachesHooksAndRoutes(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	var observed atomic.Int32
	check := func(request Request) {
		if request.ClientIdentity != "client:native-git" {
			t.Errorf("listener identity lost: %q", request.ClientIdentity)
		}
		observed.Add(1)
	}
	server, err := Start(context.Background(), Options{ClientIdentity: "client:native-git",
		RequestHooks:    []RequestHook{func(_ context.Context, request Request) (ResponseHook, error) { check(request); return nil, nil }},
		RouteForRequest: func(request Request) (*OutboundRoute, error) { check(request); return &OutboundRoute{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	address, _ := url.Parse(server.ClientConfig().URL)
	transport := &http.Transport{Proxy: http.ProxyURL(address)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || observed.Load() != 2 {
		t.Fatal("listener context did not reach both hooks and routing")
	}
}

func TestClientIdentityDoesNotLeakIntoIndependentHookRequests(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	var metadataRequests atomic.Int32
	metadata := NewTransport(Options{RouteForRequest: func(request Request) (*OutboundRoute, error) {
		if request.ClientIdentity != "" {
			t.Errorf("manager TLS policy leaked into metadata request: %q", request.ClientIdentity)
		}
		metadataRequests.Add(1)
		return &OutboundRoute{}, nil
	}})
	defer metadata.CloseIdleConnections()
	query := func(ctx context.Context) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
		response, err := (&http.Client{Transport: metadata}).Do(request)
		if err != nil {
			t.Error(err)
			return
		}
		_ = response.Body.Close()
	}
	server, err := Start(context.Background(), Options{ClientIdentity: "client:manager", RouteForRequest: func(request Request) (*OutboundRoute, error) {
		if request.ClientIdentity != "client:manager" {
			t.Error("forwarded request lost its manager identity")
		}
		return &OutboundRoute{}, nil
	}, RequestHooks: []RequestHook{func(ctx context.Context, request Request) (ResponseHook, error) {
		if request.ClientIdentity != "client:manager" {
			t.Error("hook lost observed identity")
		}
		query(ctx)
		return func(ctx context.Context, _ Response) (*ResponseBodyHook, error) { query(ctx); return nil, nil }, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	address, _ := url.Parse(server.ClientConfig().URL)
	transport := &http.Transport{Proxy: http.ProxyURL(address)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if metadataRequests.Load() != 2 {
		t.Fatal("metadata requests did not cover both hook contexts")
	}
}
