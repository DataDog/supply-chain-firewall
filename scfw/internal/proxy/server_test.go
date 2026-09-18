// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func closeProxy(t *testing.T, server *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("Server.Close() returned unexpected error: %v", err)
	}
}

func proxyGet(server *Server, requestURL string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+server.authSecret)
	return http.DefaultClient.Do(request)
}

type blockingWriter struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
}

func (writer *blockingWriter) Write(data []byte) (int, error) {
	writer.startedOnce.Do(func() { close(writer.started) })
	<-writer.release
	return len(data), nil
}

func TestServerRoutesDefaultAndScopedRegistries(t *testing.T) {
	type receivedRequest struct {
		server string
		path   string
		query  string
	}
	var requestsMu sync.Mutex
	var requests []receivedRequest
	recorder := func(name string) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			requestsMu.Lock()
			requests = append(requests, receivedRequest{name, request.URL.EscapedPath(), request.URL.RawQuery})
			requestsMu.Unlock()
			writer.Header().Set("Content-Type", "application/json")
			fmt.Fprint(writer, `{}`)
		}
	}
	defaultRegistry := httptest.NewServer(recorder("default"))
	defer defaultRegistry.Close()
	scopedRegistry := httptest.NewServer(recorder("scoped"))
	defer scopedRegistry.Close()

	var output bytes.Buffer
	server, err := Start(NPMConfig{
		Registry: mustParseURL(t, defaultRegistry.URL+"/npm/"),
		ScopedRegistries: map[string]*url.URL{
			"@private": mustParseURL(t, scopedRegistry.URL+"/packages/"),
		},
	}, &output)
	if err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}

	for _, requestURL := range []string{
		server.URL() + "left-pad?cache=bust",
		server.scopedRegistryURLs()["@private"] + "@private%2fsecret",
	} {
		response, err := proxyGet(server, requestURL)
		if err != nil {
			t.Fatalf("GET %q: %v", requestURL, err)
		}
		response.Body.Close()
	}
	closeProxy(t, server)

	requestsMu.Lock()
	defer requestsMu.Unlock()
	if got, want := requests, []receivedRequest{{"default", "/npm/left-pad", "cache=bust"}, {"scoped", "/packages/@private%2fsecret", ""}}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("requests = %+v, want %+v", got, want)
	}
	if strings.Contains(output.String(), "cache=bust") {
		t.Errorf("request log leaks query parameters: %q", output.String())
	}
	for _, want := range []string{"REQUEST GET " + defaultRegistry.URL + "/npm/left-pad", "REQUEST GET " + scopedRegistry.URL + "/packages/@private%2fsecret", `RESPONSE BODY "{}"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log %q does not contain %q", output.String(), want)
		}
	}
}

func TestServerRejectsCallerWithOnlyRegistryURL(t *testing.T) {
	upstreamCalled := make(chan struct{}, 1)
	registry := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalled <- struct{}{}
	}))
	defer registry.Close()
	server, err := Start(NPMConfig{Registry: mustParseURL(t, registry.URL+"/")}, io.Discard)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	response, err := http.Get(server.URL() + "pkg")
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	select {
	case <-upstreamCalled:
		t.Fatal("unauthenticated caller reached upstream registry")
	default:
	}
	closeProxy(t, server)
}

func TestServerSynthesizesConfiguredHTTPStatusWithoutCallingRegistry(t *testing.T) {
	upstreamCalled := make(chan struct{}, 1)
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		upstreamCalled <- struct{}{}
		writer.WriteHeader(http.StatusOK)
	}))
	defer registry.Close()

	var output bytes.Buffer
	server, err := StartWithOptions(
		NPMConfig{
			Registry:         mustParseURL(t, registry.URL+"/"),
			ScopedRegistries: map[string]*url.URL{},
			caFile:           filepath.Join(t.TempDir(), "missing-ca.pem"),
		},
		&output,
		Options{HTTPStatus: http.StatusServiceUnavailable},
	)
	if err != nil {
		t.Fatalf("StartWithOptions() returned unexpected error: %v", err)
	}
	response, err := proxyGet(server, server.URL()+"pkg")
	if err != nil {
		t.Fatalf("synthetic request: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read synthetic response: %v", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || len(body) != 0 {
		t.Errorf("synthetic response = status %d body %q", response.StatusCode, body)
	}
	select {
	case <-upstreamCalled:
		t.Fatal("synthetic response contacted upstream registry")
	default:
	}
	closeProxy(t, server)
	for _, want := range []string{"REQUEST GET " + registry.URL + "/pkg", "RESPONSE 503 GET", `RESPONSE BODY ""`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log %q does not contain %q", output.String(), want)
		}
	}
}

func TestStartWithOptionsRejectsInvalidHTTPStatus(t *testing.T) {
	_, err := StartWithOptions(NPMConfig{Registry: mustParseURL(t, "https://registry.example/")}, io.Discard, Options{HTTPStatus: 199})
	if err == nil || !strings.Contains(err.Error(), "between 200 and 599") {
		t.Fatalf("StartWithOptions() error = %v, want range error", err)
	}
}

func TestServerRewritesForwardsAndRedactsResponseURLs(t *testing.T) {
	var tarballRequests int
	tarballServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		tarballRequests++
		if request.URL.String() != "/pkg.tgz?signature=secret" {
			t.Errorf("tarball URL = %q", request.URL.String())
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(writer, "package contents")
	}))
	defer tarballServer.Close()
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/vnd.npm.install-v1+json")
		json.NewEncoder(writer).Encode(map[string]any{
			"name":  "pkg",
			"token": "secret-token",
			"versions": map[string]any{"1.0.0": map[string]any{
				"dist": map[string]string{"tarball": tarballServer.URL + "/pkg.tgz?signature=secret"},
			}},
		})
	}))
	defer registry.Close()

	var output bytes.Buffer
	server, err := Start(NPMConfig{Registry: mustParseURL(t, registry.URL+"/"), ScopedRegistries: map[string]*url.URL{}}, &output)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	response, err := proxyGet(server, server.URL()+"pkg")
	if err != nil {
		t.Fatalf("metadata request: %v", err)
	}
	var metadata struct {
		Token    string `json:"token"`
		Versions map[string]struct {
			Dist map[string]string `json:"dist"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	response.Body.Close()
	if metadata.Token != "secret-token" {
		t.Errorf("proxied response was unexpectedly redacted: %q", metadata.Token)
	}
	rewrittenTarball := metadata.Versions["1.0.0"].Dist["tarball"]
	if !strings.HasPrefix(rewrittenTarball, "http://"+server.baseURL.Host+server.forwardPrefix) {
		t.Fatalf("tarball URL was not rewritten: %q", rewrittenTarball)
	}
	tarballResponse, err := proxyGet(server, rewrittenTarball)
	if err != nil {
		t.Fatalf("tarball request: %v", err)
	}
	tarballBody, err := io.ReadAll(tarballResponse.Body)
	tarballResponse.Body.Close()
	if err != nil || string(tarballBody) != "package contents" || tarballRequests != 1 {
		t.Fatalf("tarball result = body %q requests %d err %v", tarballBody, tarballRequests, err)
	}
	closeProxy(t, server)

	for _, want := range []string{`\"token\":\"[REDACTED]\"`, tarballServer.URL + "/pkg.tgz", `RESPONSE BODY OMITTED content_type="application/octet-stream"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log %q does not contain %q", output.String(), want)
		}
	}
	for _, sensitive := range []string{"secret-token", "signature=secret", "package contents"} {
		if strings.Contains(output.String(), sensitive) {
			t.Errorf("log %q leaks %q", output.String(), sensitive)
		}
	}
}

func TestServerRestoresExistingLockfileDestinationAfterNPMHostReplacement(t *testing.T) {
	var received string
	artifactServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = request.URL.String()
		fmt.Fprint(writer, "artifact")
	}))
	defer artifactServer.Close()
	registry := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("artifact was incorrectly sent to configured registry")
	}))
	defer registry.Close()
	artifactURL := mustParseURL(t, artifactServer.URL+"/artifact.tgz?download=1")
	server, err := Start(NPMConfig{
		Registry:             mustParseURL(t, registry.URL+"/"),
		ScopedRegistries:     map[string]*url.URL{},
		lockfileDestinations: map[string]*url.URL{lockfileDestinationKey(artifactURL): artifactURL},
	}, io.Discard)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	response, err := proxyGet(server, server.URL()+"artifact.tgz?download=1")
	if err != nil {
		t.Fatalf("artifact request: %v", err)
	}
	response.Body.Close()
	closeProxy(t, server)
	if received != "/artifact.tgz?download=1" {
		t.Errorf("artifact destination = %q", received)
	}
}

func TestServerForwardsRegistryAuthentication(t *testing.T) {
	var authorization string
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{}`)
	}))
	defer registry.Close()
	registryURL := mustParseURL(t, registry.URL+"/")
	server, err := Start(NPMConfig{
		Registry: registryURL,
		credentials: map[string]npmCredentials{
			normalizeCredentialPrefix("//" + registryURL.Host + "/"): {token: "registry-token"},
		},
	}, io.Discard)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	response, err := proxyGet(server, server.URL()+"pkg")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	response.Body.Close()
	closeProxy(t, server)
	if authorization != "Bearer registry-token" {
		t.Errorf("Authorization = %q", authorization)
	}
}

func TestServerUsesNPMCertificateAuthority(t *testing.T) {
	registry := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{}`)
	}))
	defer registry.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})
	server, err := Start(NPMConfig{
		Registry:         mustParseURL(t, registry.URL+"/"),
		ScopedRegistries: map[string]*url.URL{},
		caCertificates:   []string{string(certificate)},
	}, io.Discard)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	response, err := proxyGet(server, server.URL()+"pkg")
	if err != nil {
		t.Fatalf("request through npm CA transport: %v", err)
	}
	response.Body.Close()
	closeProxy(t, server)
}

func TestServerResponseDoesNotWaitForLogOutput(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"name":"pkg"}`)
	}))
	defer registry.Close()
	output := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	server, err := Start(NPMConfig{Registry: mustParseURL(t, registry.URL+"/")}, output)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	released := false
	defer func() {
		if !released {
			close(output.release)
		}
		closeProxy(t, server)
	}()
	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := proxyGet(server, server.URL()+"pkg")
		if requestErr == nil {
			_, requestErr = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		requestDone <- requestErr
	}()
	select {
	case <-output.started:
	case <-time.After(time.Second):
		t.Fatal("log writer did not write")
	}
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatalf("proxied request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxied response waited for blocked log output")
	}
	close(output.release)
	released = true
}

func TestServerShutdownTimeoutKeepsLoggerAvailableToActiveHandlers(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseRequest
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"name":"pkg"}`)
	}))
	defer registry.Close()
	server, err := Start(NPMConfig{Registry: mustParseURL(t, registry.URL+"/")}, io.Discard)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := proxyGet(server, server.URL()+"pkg")
		if requestErr == nil {
			_, requestErr = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		requestDone <- requestErr
	}()
	<-requestStarted
	expiredContext, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Close(expiredContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close() error = %v, want cancellation", err)
	}
	close(releaseRequest)
	if err := <-requestDone; err != nil {
		t.Fatalf("active request after timed-out shutdown: %v", err)
	}
	closeProxy(t, server)
}

func TestServerMarksEmptyJSONResponseBodyAsInvalid(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer registry.Close()
	var output bytes.Buffer
	server, err := Start(NPMConfig{Registry: mustParseURL(t, registry.URL+"/")}, &output)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	response, err := proxyGet(server, server.URL()+"pkg")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	response.Body.Close()
	closeProxy(t, server)
	if !strings.Contains(output.String(), "RESPONSE BODY OMITTED reason=invalid_json") {
		t.Errorf("log = %q, want invalid_json omission", output.String())
	}
}
