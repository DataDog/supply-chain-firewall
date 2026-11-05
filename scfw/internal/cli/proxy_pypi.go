// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// pyPIProxyController owns PyPI discovery and resolution for one invocation.
// The shared evaluator receives resolved packages and owns policy decisions.
type pyPIProxyController struct {
	packageEvaluator *proxyPackageEvaluator
	metadata         pypi.MetadataCache
	metadataClient   *http.Client
	resolveDate      func(context.Context, string, string, string) (time.Time, error)

	mutex             sync.Mutex
	classifier        *pypi.RequestClassifier
	classifierOptions pypi.RequestClassifierOptions
}

func newPyPIProxyController(
	packageEvaluator *proxyPackageEvaluator,
	classifierOptions pypi.RequestClassifierOptions,
) (*pyPIProxyController, error) {
	classifier, err := pypi.NewRequestClassifier(classifierOptions)
	if err != nil {
		return nil, err
	}
	return &pyPIProxyController{
		packageEvaluator:  packageEvaluator,
		classifier:        classifier,
		classifierOptions: classifierOptions,
		resolveDate:       pypi.ResolvePublishDate,
	}, nil
}

func (e *pyPIProxyController) configure(runContext context.Context, options proxy.Options) proxy.Options {
	e.packageEvaluator.runContext = runContext
	e.metadataClient = newPublicationHTTPClient(options)
	e.resolveDate = func(ctx context.Context, name, version, source string) (time.Time, error) {
		return pypi.ResolvePublishDateWithClient(ctx, e.metadataClient, name, version, source)
	}
	options.RequestHooks = append(options.RequestHooks, func(ctx context.Context, request proxy.Request) (proxy.ResponseHook, error) {
		return e.pypiHandler().HandleRequest(ctx, request)
	})
	return options
}

func (e *pyPIProxyController) pypiHandler() pypi.ProxyHandler {
	return pypi.ProxyHandler{
		RunContext:       e.packageEvaluator.runContext,
		Client:           e.metadataClient,
		Metadata:         &e.metadata,
		Classifier:       e.classifierSnapshot(),
		EvaluateArtifact: e.evaluateArtifactRequest,
	}
}

func (e *pyPIProxyController) evaluateArtifactRequest(requestContext context.Context, artifact pypi.Artifact) error {
	// Resolve each file before consulting the policy cache: distributions from
	// the same release can have different sources and upload times.
	pkg, publishErr := e.resolveArtifact(e.packageEvaluator.runContext, artifact)
	return e.packageEvaluator.evaluatePackage(requestContext, pkg, publishErr)
}

func (e *pyPIProxyController) resolveArtifact(ctx context.Context, artifact pypi.Artifact) (pm.Package, error) {
	pkg := pm.Package{Ecosystem: ecosystem.PYPI, Name: artifact.Name, Version: artifact.Version, Source: artifact.Source}
	publishDate, err := e.metadata.ResolveArtifactPublishDate(ctx, e.metadataClient, artifact, e.resolveDate)
	if err == nil {
		pkg.PublishDate = publishDate.UTC()
	}
	return pkg, err
}

func (e *pyPIProxyController) classifierSnapshot() *pypi.RequestClassifier {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.classifier
}

func (e *pyPIProxyController) addClassifierContext(options pypi.RequestClassifierOptions) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	combined := e.classifierOptions
	combined.SimpleIndexURLs = append(combined.SimpleIndexURLs, options.SimpleIndexURLs...)
	combined.DirectArtifactURLs = append(combined.DirectArtifactURLs, options.DirectArtifactURLs...)
	classifier, err := pypi.NewRequestClassifier(combined)
	if err != nil {
		return err
	}
	e.classifierOptions, e.classifier = combined, classifier
	return nil
}

func newPackageManagerPyPIController(manager pm.PackageManager, command []string, evaluator *proxyPackageEvaluator) (ecosystemProxyController, error) {
	controller, err := newPyPIProxyController(evaluator, pypi.RequestClassifierOptions{})
	if err != nil {
		return nil, err
	}
	return controller.forPackageManager(manager, command)
}

func (e *pyPIProxyController) forPackageManager(manager pm.PackageManager, command []string) (ecosystemProxyController, error) {
	if provider, ok := manager.(interface {
		PyPIClassifierOptions([]string) (pypi.RequestClassifierOptions, error)
	}); ok {
		options, err := provider.PyPIClassifierOptions(command)
		if err != nil {
			return nil, err
		}
		if err := e.addClassifierContext(options); err != nil {
			return nil, err
		}
	}
	return e.configure, nil
}
