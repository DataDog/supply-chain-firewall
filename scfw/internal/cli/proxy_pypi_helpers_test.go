// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// testPyPIController connects the public ecosystem hook to the CLI evaluator.
// Tests may supply registry responses before the hook first handles traffic.
type testPyPIController struct {
	packageEvaluator  *proxyPackageEvaluator
	metadataClient    *http.Client
	resolveDate       func(context.Context, string, string, string) (time.Time, error)
	classifierOptions pypi.RequestClassifierOptions
	metadata          testPyPIMetadata
	mutex             sync.Mutex
	hook              proxy.RequestHook
}

func newTestPyPIController(
	ctx context.Context, timestamp time.Time, command []string,
	manager, executable, repository string,
	evaluator evaluation.Evaluator, reporter evaluation.Reporter, output io.Writer,
) *testPyPIController {
	controller := &testPyPIController{
		packageEvaluator: newProxyPackageEvaluator(ctx, timestamp, command, manager, executable, repository, evaluator, reporter, output),
		resolveDate:      pypi.ResolvePublishDate,
	}
	controller.metadata.controller = controller
	return controller
}

func (c *testPyPIController) pypiHandler() *testPyPIController { return c }

func (c *testPyPIController) HandleRequest(ctx context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	c.mutex.Lock()
	if c.hook == nil {
		hook, err := pypi.NewProxyHook(c.packageEvaluator.runContext, pypi.ProxyHookOptions{
			Client:            c.metadataClient,
			ClassifierOptions: c.classifierOptions,
			EvaluatePackage:   c.packageEvaluator.evaluatePackage,
			ResolvePublishDate: func(ctx context.Context, name, version, source string) (time.Time, error) {
				return c.resolveDate(ctx, name, version, source)
			},
		})
		if err != nil {
			c.mutex.Unlock()
			return nil, err
		}
		c.hook = hook
	}
	hook := c.hook
	c.mutex.Unlock()
	return hook(ctx, request)
}

func (c *testPyPIController) ObserveMetadataHeaders(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	hook, err := c.HandleRequest(ctx, response.Request)
	if err != nil || hook == nil {
		return nil, err
	}
	return hook(ctx, response)
}

type testPyPIMetadata struct{ controller *testPyPIController }

func (m testPyPIMetadata) Observe(endpoint url.URL, header http.Header, body []byte) error {
	response := proxy.Response{
		Request:    proxy.Request{Method: http.MethodGet, URL: endpoint},
		StatusCode: http.StatusOK, Header: header, Body: body,
	}
	hook, err := m.controller.ObserveMetadataHeaders(context.Background(), response)
	if err != nil {
		return err
	}
	if hook == nil {
		return fmt.Errorf("no metadata observer for %s", endpoint.String())
	}
	return hook.Handle(context.Background(), response)
}

func (c *testPyPIController) setClassifierOptions(options pypi.RequestClassifierOptions) {
	c.classifierOptions = options
	c.hook = nil
}

func (c *testPyPIController) configure(ctx context.Context, options proxy.Options) proxy.Options {
	c.packageEvaluator.runContext = ctx
	c.metadataClient = newPublicationHTTPClient(options)
	c.resolveDate = func(ctx context.Context, name, version, source string) (time.Time, error) {
		return pypi.ResolvePublishDateWithClient(ctx, c.metadataClient, name, version, source)
	}
	c.hook = nil
	options.RequestHooks = append(options.RequestHooks, c.HandleRequest)
	return options
}

func configureTestPyPIController(c *testPyPIController, options pypi.RequestClassifierOptions) (func(context.Context, proxy.Options) proxy.Options, error) {
	if _, err := pypi.NewRequestClassifier(options); err != nil {
		return nil, err
	}
	c.setClassifierOptions(options)
	return c.configure, nil
}
