// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyHandlerPassesAdvertisedArtifactToPolicyCallback(t *testing.T) {
	cdnOpaqueWheelFixture := readPyPIJSONFixture(t, "metadata/cdn-opaque-wheel")
	classifier, err := NewRequestClassifier(RequestClassifierOptions{
		SimpleIndexURLs: []string{"https://index.example/python-packages/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	blocked := errors.New("blocked by caller")
	var artifacts []Artifact
	requestContext := context.WithValue(context.Background(), struct{}{}, "request context")
	handler := ProxyHandler{
		RunContext: context.Background(),
		Metadata:   &MetadataCache{},
		Classifier: classifier,
		EvaluateArtifact: func(ctx context.Context, artifact Artifact) error {
			if ctx != requestContext {
				t.Error("artifact callback did not receive the request context")
			}
			artifacts = append(artifacts, artifact)
			return blocked
		},
	}
	metadataURL, err := url.Parse("https://index.example/python-packages/project/")
	if err != nil {
		t.Fatal(err)
	}
	request := proxy.Request{Method: http.MethodGet, URL: *metadataURL}
	responseHook, err := handler.HandleRequest(requestContext, request)
	if err != nil || responseHook == nil {
		t.Fatalf("metadata response hook = %v, error = %v", responseHook != nil, err)
	}
	response := proxy.Response{
		Request:    request,
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/vnd.pypi.simple.v1+json"}},
	}
	bodyHook, err := responseHook(requestContext, response)
	if err != nil || bodyHook == nil {
		t.Fatalf("metadata body hook = %v, error = %v", bodyHook != nil, err)
	}
	response.Body = []byte(cdnOpaqueWheelFixture)
	if err := bodyHook.Handle(requestContext, response); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 0 {
		t.Fatal("metadata request invoked the artifact policy callback")
	}

	artifactURL, err := url.Parse("https://cdn.example/objects/opaque?id=wheel")
	if err != nil {
		t.Fatal(err)
	}
	hook, err := handler.HandleRequest(requestContext, proxy.Request{Method: http.MethodGet, URL: *artifactURL})
	if hook != nil || !errors.Is(err, blocked) {
		t.Fatalf("artifact response hook = %v, error = %v; want caller's block", hook != nil, err)
	}
	if len(artifacts) != 1 || artifacts[0].Name != "project" || artifacts[0].Version != "1.0" || artifacts[0].Source != "https://cdn.example/objects/opaque" {
		t.Fatalf("artifact callback inputs = %#v", artifacts)
	}

	// PEP 658 metadata associated with an opaque wheel bypasses policy.
	artifactURL.Path += ".metadata"
	if _, err := handler.HandleRequest(requestContext, proxy.Request{Method: http.MethodGet, URL: *artifactURL}); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 {
		t.Fatal("core metadata invoked the artifact policy callback")
	}
}

func TestProxyHandlerPassesHTMLWithoutInspectionOrRefresh(t *testing.T) {
	for _, contentType := range []string{"text/html; charset=utf-8", "application/vnd.pypi.simple.v1+html", "application/xhtml+xml"} {
		for _, status := range []int{http.StatusOK, http.StatusNotModified} {
			classifier, err := NewRequestClassifier(RequestClassifierOptions{})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			handler := ProxyHandler{RunContext: context.Background(), Metadata: &MetadataCache{}, Classifier: classifier,
				Client:           &http.Client{Transport: htmlUnexpectedTransport{t: t}},
				EvaluateArtifact: func(context.Context, Artifact) error { calls++; return nil },
			}
			target, _ := url.Parse("https://pypi.org/simple/project/")
			request := proxy.Request{Method: http.MethodGet, URL: *target}
			responseHook, err := handler.HandleRequest(context.Background(), request)
			if err != nil || responseHook == nil {
				t.Fatalf("metadata headers hook=%v err=%v", responseHook != nil, err)
			}
			header := http.Header{"Content-Type": {contentType}, "Content-Encoding": {"unsupported"}, "Content-Length": {"999999999"}}
			bodyHook, err := responseHook(context.Background(), proxy.Response{Request: request, StatusCode: status, Header: header})
			if err != nil || bodyHook != nil || calls != 0 {
				t.Fatalf("HTML was inspected: bodyHook=%v err=%v evaluations=%d", bodyHook != nil, err, calls)
			}
			if handler.Metadata.HasObserved(*target) {
				t.Fatal("HTML marked as parsed JSON metadata")
			}
		}
	}
}

type htmlUnexpectedTransport struct{ t *testing.T }

func (transport htmlUnexpectedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.t.Error("HTML response triggered an independent metadata refresh")
	return nil, errors.New("unexpected HTML metadata refresh")
}

func TestProxyHandlerBlocksArtifactsAtMetadataRedirectDestinations(t *testing.T) {
	for _, test := range []struct {
		name, contentType, filename string
		hop                         bool
	}{
		{"HTML to wheel", "text/html", "project-1.0-py3-none-any.whl", false},
		{"JSON to sdist", "application/vnd.pypi.simple.v1+json", "project-1.0.tar.gz", false},
		{"HTML redirect chain", "application/vnd.pypi.simple.v1+html", "project-1.0.tar.gz", true},
		{"JSON redirect chain", "application/json", "project-1.0-py3-none-any.whl", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var artifactHits, evaluations atomic.Int32
			artifactPath := "/packages/" + test.filename
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/simple/project/", "/listing/":
					location := artifactPath
					if test.hop && r.URL.Path == "/simple/project/" {
						location = "/listing/"
					}
					w.Header().Set("Content-Type", test.contentType)
					w.Header().Set("Location", location)
					w.WriteHeader(http.StatusFound)
				case artifactPath:
					artifactHits.Add(1)
					w.Header().Set("Content-Type", "application/octet-stream")
					_, _ = io.WriteString(w, "artifact must not be forwarded")
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			classifier, err := NewRequestClassifier(RequestClassifierOptions{SimpleIndexURLs: []string{upstream.URL + "/simple/"}})
			if err != nil {
				t.Fatal(err)
			}
			handler := ProxyHandler{RunContext: context.Background(), Metadata: &MetadataCache{}, Classifier: classifier,
				EvaluateArtifact: func(_ context.Context, artifact Artifact) error {
					evaluations.Add(1)
					if artifact.Name != "project" || artifact.Version != "1.0" || artifact.Filename != test.filename {
						t.Errorf("incorrect redirected artifact: %#v", artifact)
					}
					return errors.New("blocked by policy")
				},
			}
			server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{handler.HandleRequest}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			// Following the redirect and requesting its registered destination
			// again must both evaluate the artifact before contacting upstream.
			for _, path := range []string{"/simple/project/", artifactPath} {
				response, err := client.Get(upstream.URL + path)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusForbidden {
					t.Fatalf("%s status=%d, want 403", path, response.StatusCode)
				}
			}
			if artifactHits.Load() != 0 || evaluations.Load() != 2 {
				t.Fatalf("artifact hits=%d evaluations=%d, want 0 and 2", artifactHits.Load(), evaluations.Load())
			}
		})
	}
}
