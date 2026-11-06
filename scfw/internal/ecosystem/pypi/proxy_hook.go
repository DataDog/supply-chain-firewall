// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// ProxyHookOptions supplies invocation-specific registry access and policy wiring.
type ProxyHookOptions struct {
	Client            *http.Client
	ClassifierOptions RequestClassifierOptions
	// EvaluatePackage receives a resolved distribution and any publication error.
	// Its context belongs to the request; registry resolution uses the run context.
	// The callback may run concurrently. Returning an error rejects the download.
	EvaluatePackage func(context.Context, pm.Package, error) error
	// ResolvePublishDate overrides the registry fallback. By default it uses Client.
	ResolvePublishDate func(context.Context, string, string, string) (time.Time, error)
}

// NewProxyHook creates independent PyPI discovery and resolution state for one run.
// The caller owns Client and must preserve the package manager's proxy/TLS settings.
func NewProxyHook(runContext context.Context, options ProxyHookOptions) (proxy.RequestHook, error) {
	handler, err := newProxyHook(runContext, options)
	if err != nil {
		return nil, err
	}
	return handler.HandleRequest, nil
}

type proxyHook struct {
	ProxyHandler
	resolveDate func(context.Context, string, string, string) (time.Time, error)
}

func newProxyHook(runContext context.Context, options ProxyHookOptions) (*proxyHook, error) {
	if runContext == nil || options.EvaluatePackage == nil {
		return nil, errors.New("PyPI proxy hook requires a run context and package evaluation callback")
	}
	classifier, err := NewRequestClassifier(options.ClassifierOptions)
	if err != nil {
		return nil, err
	}
	resolveDate := options.ResolvePublishDate
	if resolveDate == nil {
		resolveDate = func(ctx context.Context, name, version, source string) (time.Time, error) {
			return ResolvePublishDateWithClient(ctx, options.Client, name, version, source)
		}
	}
	handler := &proxyHook{
		ProxyHandler: ProxyHandler{
			RunContext: runContext,
			Client:     options.Client,
			Metadata:   &MetadataCache{},
			Classifier: classifier,
		},
		resolveDate: resolveDate,
	}
	handler.EvaluateArtifact = func(requestContext context.Context, artifact Artifact) error {
		// Resolve each distribution before consulting the shared policy cache:
		// files in the same release can have different sources and upload times.
		pkg, publicationErr := handler.resolveArtifact(runContext, artifact)
		return options.EvaluatePackage(requestContext, pkg, publicationErr)
	}
	return handler, nil
}

func (h *proxyHook) resolveArtifact(ctx context.Context, artifact Artifact) (pm.Package, error) {
	pkg := pm.Package{Ecosystem: common.PYPI, Name: artifact.Name, Version: artifact.Version, Source: artifact.Source}
	publishDate, err := h.Metadata.ResolveArtifactPublishDate(ctx, h.Client, artifact, h.resolveDate)
	if err == nil {
		pkg.PublishDate = publishDate.UTC()
	}
	return pkg, err
}
