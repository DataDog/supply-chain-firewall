// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyHandlerPassesAdvertisedArtifactToPolicyCallback(t *testing.T) {
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
	response.Body = []byte(`{"files":[{"filename":"project-1.0-py3-none-any.whl","url":"https://cdn.example/objects/opaque?id=wheel"}]}`)
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
