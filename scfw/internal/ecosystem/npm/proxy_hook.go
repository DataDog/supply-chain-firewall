// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// ProxyHookOptions supplies invocation-specific registry access and policy wiring.
type ProxyHookOptions struct {
	ValidateArtifactRequest   func(proxy.Request) error
	MapArtifactURL            func(string) (string, error)
	NonRegistrySources        []NonRegistrySource
	ResolveNonRegistryRequest func(proxy.Request) (NonRegistrySource, bool)
	RegistryRequestName       func(proxy.Request) (string, bool)
	ExpectedArtifacts         []ExpectedArtifact
	// Client fetches packuments. The caller owns it and must preserve the
	// package manager's proxy/TLS settings.
	Client            *http.Client
	ClassifierOptions ClassifierOptions
	// EvaluatePackage receives a resolved tarball and any publication error.
	// Its context belongs to the request; registry resolution uses the run context.
	// The callback may run concurrently. Returning an error rejects the download.
	EvaluatePackage  func(context.Context, pm.Package, error) error
	EvaluateResult   func(context.Context, pm.ArtifactResult) error
	Authorization    func(*url.URL) string
	RegistryArtifact func(string, string, string) (Artifact, error)
}

// NewProxyHook creates independent npm classification and publication state for one run.
func NewProxyHook(runContext context.Context, options ProxyHookOptions) (proxy.RequestHook, error) {
	handler, err := newProxyHook(runContext, options)
	if err != nil {
		return nil, err
	}
	if options.EvaluateResult != nil {
		return newArtifactProxyHook(runContext, handler, options), nil
	}
	return handler.HandleRequest, nil
}

type proxyHook struct {
	ProxyHandler
	client       *http.Client
	publications *PublicationCache
}

func newProxyHook(runContext context.Context, options ProxyHookOptions) (*proxyHook, error) {
	if runContext == nil || options.EvaluatePackage == nil {
		return nil, errors.New("npm proxy hook requires a run context and package evaluation callback")
	}
	classifier, err := NewClassifier(options.ClassifierOptions)
	if err != nil {
		return nil, err
	}
	handler := &proxyHook{
		ProxyHandler: ProxyHandler{Classifier: classifier},
		client:       options.Client,
		publications: &PublicationCache{},
	}
	handler.EvaluateArtifact = func(requestContext context.Context, artifact Artifact) error {
		// Publication data is resolved for the run, not this request, so a client
		// abandoning one request does not fail the lookup for its retries.
		pkg, publicationErr := handler.resolveArtifact(runContext, artifact)
		return options.EvaluatePackage(requestContext, pkg, publicationErr)
	}
	return handler, nil
}

func (h *proxyHook) resolveArtifact(ctx context.Context, artifact Artifact) (pm.Package, error) {
	pkg := pm.Package{Ecosystem: common.NPM, Name: artifact.Name, Version: artifact.Version, Source: artifact.Source}
	publishDate, err := h.publications.Resolve(ctx, h.client, artifact)
	if err == nil {
		pkg.PublishDate = publishDate.UTC()
	}
	return pkg, err
}
