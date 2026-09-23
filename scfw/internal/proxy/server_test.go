// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestObservedRequestRemovesURLCredentials(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://registry-token:secret@registry.example.test/package", nil)
	if err != nil {
		t.Fatalf("NewRequest() returned error: %v", err)
	}

	got := observedRequest(request)
	if got.URL != "https://registry.example.test/package" {
		t.Errorf("observedRequest().URL = %q, want URL without credentials", got.URL)
	}
}

func TestServerInterceptsHTTPSAndCleansUpCertificate(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/package" {
			t.Errorf("upstream request path = %q, want /package", request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("ReadAll(upstream request) returned error: %v", err)
		}
		wantBody := "requested"
		if request.Method != http.MethodGet {
			wantBody = "ignored"
		}
		if string(body) != wantBody {
			t.Errorf("upstream request body = %q, want %q", body, wantBody)
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("observed"))
	}))
	defer upstream.Close()

	requests := make(chan Request, 1)
	responses := make(chan Response, 1)
	upstreamTransport := upstream.Client().Transport.(*http.Transport).Clone()
	upstreamTransport.Proxy = nil

	server, err := Start(Options{
		OnRequest: func(request Request) error {
			requests <- request
			return nil
		},
		OnResponse: func(response Response) { responses <- response },
		Transport:  upstreamTransport,
	})
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	certificatePath := server.CertificatePath()
	if host, _, err := net.SplitHostPort(server.listener.Addr().String()); err != nil || host != "127.0.0.1" {
		t.Fatalf("proxy listener = %q, want IPv4 loopback: %v", server.listener.Addr(), err)
	}

	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatalf("ReadFile(certificate) returned error: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("AppendCertsFromPEM() rejected proxy certificate")
	}
	proxyURL, err := url.Parse(server.URL())
	if err != nil {
		t.Fatalf("Parse(proxy URL) returned error: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/package", strings.NewReader("requested"))
	if err != nil {
		t.Fatalf("NewRequest() returned error: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET through proxy returned error: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(response) returned error: %v", err)
	}
	if response.StatusCode != http.StatusCreated || string(body) != "observed" {
		t.Errorf("response = (%d, %q), want (%d, observed)", response.StatusCode, body, http.StatusCreated)
	}

	observedRequest := <-requests
	if observedRequest.Method != http.MethodGet || observedRequest.URL != upstream.URL+"/package" {
		t.Errorf("observed request = %#v", observedRequest)
	}
	observedResponse := <-responses
	if observedResponse.StatusCode != http.StatusCreated || observedResponse.Request != observedRequest {
		t.Errorf("observed response = %#v", observedResponse)
	}

	response, err = client.Post(upstream.URL+"/package", "text/plain", strings.NewReader("ignored"))
	if err != nil {
		t.Fatalf("POST through proxy returned error: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if len(requests) != 0 || len(responses) != 0 {
		t.Errorf("non-GET request was observed: requests=%d responses=%d", len(requests), len(responses))
	}

	client.CloseIdleConnections()
	if err := server.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if _, err := os.Stat(certificatePath); !os.IsNotExist(err) {
		t.Errorf("certificate still exists after Close(): %v", err)
	}
}

func TestServerRejectsGETBeforeSendingItUpstream(t *testing.T) {
	upstreamRequests := make(chan struct{}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamRequests <- struct{}{}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamTransport := upstream.Client().Transport.(*http.Transport).Clone()
	upstreamTransport.Proxy = nil
	server, err := Start(Options{
		OnRequest: func(Request) error { return errors.New("blocked by policy") },
		Transport: upstreamTransport,
	})
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	defer server.Close() //nolint:errcheck

	certificatePEM, err := os.ReadFile(server.CertificatePath())
	if err != nil {
		t.Fatalf("ReadFile(certificate) returned error: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("AppendCertsFromPEM() rejected proxy certificate")
	}
	proxyURL, err := url.Parse(server.URL())
	if err != nil {
		t.Fatalf("Parse(proxy URL) returned error: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	response, err := client.Get(upstream.URL + "/package")
	if err != nil {
		t.Fatalf("GET through proxy returned error: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(response) returned error: %v", err)
	}
	if response.StatusCode != http.StatusForbidden || string(body) != "blocked by policy\n" {
		t.Errorf("response = (%d, %q), want (%d, %q)", response.StatusCode, body, http.StatusForbidden, "blocked by policy\n")
	}
	if len(upstreamRequests) != 0 {
		t.Fatal("rejected request was sent upstream")
	}
}
