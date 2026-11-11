// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"net/http"
	"slices"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/pip"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/poetry"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/uv"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type PackageManagerFactory struct {
	Names      []string
	New        func(ctx context.Context, name, executable string) (pm.PackageManager, error)
	ProxyHooks []proxyHookFactory
}

var packageManagerFactories = []PackageManagerFactory{
	{
		Names:      uv.ExecutableNames,
		ProxyHooks: []proxyHookFactory{newPyPIProxyHook},
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return uv.NewUV(ctx, name, executable)
		},
	},
	{
		Names:      npm.NpmExecutableNames,
		ProxyHooks: []proxyHookFactory{newNpmProxyHook},
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return npm.NewNpm(ctx, name, executable)
		},
	},
	{
		Names:      pip.PipExecutableNames,
		ProxyHooks: []proxyHookFactory{newPyPIProxyHook},
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return pip.NewPip(ctx, name, executable)
		},
	},
	{
		Names: poetry.PoetryExecutableNames,
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return poetry.NewPoetry(ctx, name, executable)
		},
	},
}

func findPackageManagerFactory(name string) (PackageManagerFactory, bool) {
	for _, factory := range packageManagerFactories {
		if slices.Contains(factory.Names, name) {
			return factory, true
		}
	}
	return PackageManagerFactory{}, false
}

// proxyHookFactory binds package-manager settings to an ecosystem hook for one run.
type proxyHookFactory func(
	context.Context, pm.PackageManager, []string, *http.Client,
	func(context.Context, pm.Package, error) error,
) (proxy.RequestHook, error)

func newNpmProxyHook(
	ctx context.Context, manager pm.PackageManager, command []string, client *http.Client,
	evaluate func(context.Context, pm.Package, error) error,
) (proxy.RequestHook, error) {
	var options npmregistry.ClassifierOptions
	if provider, ok := manager.(interface {
		NpmClassifierOptions([]string) (npmregistry.ClassifierOptions, error)
	}); ok {
		var err error
		options, err = provider.NpmClassifierOptions(command)
		if err != nil {
			return nil, err
		}
	}
	return npmregistry.NewProxyHook(ctx, npmregistry.ProxyHookOptions{
		Client:            client,
		ClassifierOptions: options,
		EvaluatePackage:   evaluate,
	})
}

func newPyPIProxyHook(
	ctx context.Context, manager pm.PackageManager, command []string, client *http.Client,
	evaluate func(context.Context, pm.Package, error) error,
) (proxy.RequestHook, error) {
	var options pypi.RequestClassifierOptions
	if provider, ok := manager.(interface {
		PyPIClassifierOptions([]string) (pypi.RequestClassifierOptions, error)
	}); ok {
		var err error
		options, err = provider.PyPIClassifierOptions(command)
		if err != nil {
			return nil, err
		}
	}
	return pypi.NewProxyHook(ctx, pypi.ProxyHookOptions{
		Client:            client,
		ClassifierOptions: options,
		EvaluatePackage:   evaluate,
	})
}
