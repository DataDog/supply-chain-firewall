// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"fmt"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/githook"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// gitCheckoutPolicy maps a package manager's git checkouts to policy decisions.
type gitCheckoutPolicy func(evaluate func(context.Context, pm.Package, error) error) githook.Decide

// npmGitCheckoutPolicy evaluates npm git dependencies from their checkout.
func npmGitCheckoutPolicy(evaluate func(context.Context, pm.Package, error) error) githook.Decide {
	return func(ctx context.Context, checkout githook.Checkout) error {
		pkg, found, err := npmregistry.CheckoutPackage(checkout.Dir, checkout.Origin, checkout.SHA)
		if err != nil || !found {
			return err
		}
		if err := evaluate(ctx, pkg, nil); err != nil {
			return fmt.Errorf("%w (%s)", err, pkg.Source)
		}
		return nil
	}
}

// gitHookRunner gives the proxied command git hooks that ask decide about
// each checkout. decide is set while hooks are configured, before the command
// starts.
type gitHookRunner struct {
	pm.ProxyRunner
	executable string
	decide     *githook.Decide
	hooks      *githook.Hooks
}

func (r *gitHookRunner) ProxyOptions(command []string) (proxy.Options, error) {
	if provider, ok := r.ProxyRunner.(pm.ProxyOptionsProvider); ok {
		return provider.ProxyOptions(command)
	}
	upstream, err := r.UpstreamProxy(command)
	return proxy.Options{Upstream: upstream}, err
}

func (r *gitHookRunner) ProxyCommand(ctx context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	spec, err := r.ProxyRunner.ProxyCommand(ctx, command, config)
	if err != nil || *r.decide == nil {
		return spec, err
	}
	r.hooks, err = githook.Start(ctx, r.executable, *r.decide)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	r.hooks.Apply(&spec)
	return spec, nil
}

// Close removes the hooks once the command has finished.
func (r *gitHookRunner) Close() {
	if r.hooks != nil {
		_ = r.hooks.Close()
	}
}
