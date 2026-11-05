// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
)

func newPyPIProxyController(packageEvaluator *proxyPackageEvaluator) ecosystemProxyController {
	controller, err := newPyPIProxyControllerWithOptions(packageEvaluator, pypi.RequestClassifierOptions{})
	if err != nil {
		panic(err)
	}
	return controller
}

// newPyPIProxyControllerWithOptions is the future Python-adapter integration
// surface for arbitrary index bases and direct artifact URLs. Existing package
// managers are deliberately not wired to this controller in this change.
func newPyPIProxyControllerWithOptions(
	packageEvaluator *proxyPackageEvaluator,
	classifierOptions pypi.RequestClassifierOptions,
) (ecosystemProxyController, error) {
	classifier, err := pypi.NewRequestClassifier(classifierOptions)
	if err != nil {
		return nil, err
	}
	packageEvaluator.classifier = classifier
	return func(runContext context.Context, upstream httpproxy.Config) proxy.Options {
		packageEvaluator.runContext = runContext
		client := newPublicationHTTPClient(upstream)
		packageEvaluator.metadataClient = client
		packageEvaluator.resolveDate = func(ctx context.Context, packageEcosystem ecosystem.Ecosystem, name, version, source string) (time.Time, error) {
			if packageEcosystem != ecosystem.PYPI {
				return time.Time{}, fmt.Errorf("unsupported proxy ecosystem: %s", packageEcosystem)
			}
			return pypi.ResolvePublishDateWithClient(ctx, client, name, version, source)
		}
		return proxy.Options{
			RequestHooks: []proxy.RequestHook{packageEvaluator.pypiHandler().HandleRequest},
		}
	}, nil
}

func (e *proxyPackageEvaluator) pypiHandler() pypi.ProxyHandler {
	return pypi.ProxyHandler{
		RunContext:       e.runContext,
		Client:           e.metadataClient,
		Metadata:         &e.metadata,
		Classifier:       e.classifier,
		EvaluateArtifact: e.evaluateArtifactRequest,
	}
}
