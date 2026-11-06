// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// recordingHandler returns a handler whose policy callback records each
// artifact and returns result.
func recordingHandler(t *testing.T, result error) (ProxyHandler, func() []Artifact) {
	t.Helper()
	var mutex sync.Mutex
	var artifacts []Artifact
	handler := ProxyHandler{
		Classifier: newDefaultClassifier(t),
		EvaluateArtifact: func(_ context.Context, artifact Artifact) error {
			mutex.Lock()
			defer mutex.Unlock()
			artifacts = append(artifacts, artifact)
			return result
		},
	}
	return handler, func() []Artifact {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]Artifact(nil), artifacts...)
	}
}

func getRequest(t *testing.T, raw string) proxy.Request {
	t.Helper()
	return proxy.Request{Method: http.MethodGet, URL: *mustParseURL(t, raw), Header: http.Header{}}
}

// proxiedClient starts a proxy with handler's hook and returns a client routed through it.
func proxiedClient(t *testing.T, hook proxy.RequestHook) *http.Client {
	t.Helper()
	server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{hook}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, err := url.Parse(server.ClientConfig().URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func TestProxyHandlerEvaluatesTarballOnAnyHost(t *testing.T) {
	handler, evaluated := recordingHandler(t, nil)
	request := getRequest(t, "https://evil.example/left-pad/-/left-pad-1.3.0.tgz")
	request.Header.Set("Authorization", "Bearer t")

	hook, err := handler.HandleRequest(context.Background(), request)
	if hook != nil || err != nil {
		t.Fatalf("HandleRequest() = %v, %v; want no response hook and no error", hook != nil, err)
	}
	artifacts := evaluated()
	if len(artifacts) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(artifacts))
	}
	if artifacts[0].Name != "left-pad" || artifacts[0].Version != "1.3.0" || artifacts[0].authorization != "Bearer t" {
		t.Fatalf("evaluated %+v, want left-pad@1.3.0 carrying the request's Authorization", artifacts[0])
	}
}

func TestProxyHandlerPassesNonTarballTraffic(t *testing.T) {
	handler, evaluated := recordingHandler(t, errors.New("must not be evaluated"))
	for _, request := range []proxy.Request{
		getRequest(t, "https://registry.npmjs.org/left-pad"),
		getRequest(t, "https://registry.npmjs.org/-/v1/search?text=left-pad"),
		getRequest(t, "https://cdn.npmmirror.com/packages/left-pad/1.3.0/left-pad-1.3.0.tgz"),
		{Method: http.MethodPost, URL: *mustParseURL(t, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")},
		{Method: http.MethodHead, URL: *mustParseURL(t, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")},
	} {
		hook, err := handler.HandleRequest(context.Background(), request)
		if hook != nil || err != nil {
			t.Fatalf("%s %s: HandleRequest() = %v, %v; want it passed through untouched", request.Method, request.URL.String(), hook != nil, err)
		}
	}
	if got := len(evaluated()); got != 0 {
		t.Fatalf("evaluations = %d, want 0 for non-tarball traffic", got)
	}
}

func TestProxyHandlerReturnsPolicyError(t *testing.T) {
	errBlocked := errors.New("blocked by policy")
	handler, _ := recordingHandler(t, errBlocked)

	if _, err := handler.HandleRequest(context.Background(), getRequest(t, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")); !errors.Is(err, errBlocked) {
		t.Fatalf("HandleRequest() = %v, want the policy's rejection", err)
	}
}

func TestProxyHandlerBlocksTarballBeforeForwarding(t *testing.T) {
	var tarballHits, packumentHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/left-pad" {
			packumentHits.Add(1)
			servePackument(leftPadPackument(t), nil)(w, r)
			return
		}
		tarballHits.Add(1)
		_, _ = w.Write([]byte("tarball"))
	}))
	defer upstream.Close()
	handler, evaluated := recordingHandler(t, errors.New("blocked by policy"))
	client := proxiedClient(t, handler.HandleRequest)

	response, err := client.Get(upstream.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || tarballHits.Load() != 0 || len(evaluated()) != 1 {
		t.Fatalf("tarball: status=%d upstream hits=%d evaluations=%d, want 403, 0 and 1",
			response.StatusCode, tarballHits.Load(), len(evaluated()))
	}

	response, err = client.Get(upstream.URL + "/left-pad")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || packumentHits.Load() != 1 {
		t.Fatalf("packument: status=%d upstream hits=%d, want 200 and 1", response.StatusCode, packumentHits.Load())
	}
}

func TestProxyHandlerGatesConditionalTarballRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer upstream.Close()
	handler, evaluated := recordingHandler(t, nil)
	client := proxiedClient(t, handler.HandleRequest)

	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/left-pad/-/left-pad-1.3.0.tgz", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("If-None-Match", `"cached"`)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if got := len(evaluated()); got != 1 {
		t.Fatalf("evaluations = %d, want a conditional tarball request evaluated once", got)
	}
}
