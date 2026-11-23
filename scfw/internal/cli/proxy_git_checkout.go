// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
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
		return evaluateCheckout(ctx, evaluate, pkg, found, err)
	}
}

// yarnGitCheckoutPolicy evaluates Yarn 4 git dependencies from their checkout
// and Yarn Classic ones from the commit it archives from its clone.
func yarnGitCheckoutPolicy(evaluate func(context.Context, pm.Package, error) error) githook.Decide {
	return func(ctx context.Context, checkout githook.Checkout) error {
		if !checkout.Archive {
			pkg, found, err := npmregistry.YarnCheckoutPackage(checkout.Dir, checkout.Origin, checkout.Previous, checkout.SHA)
			return evaluateCheckout(ctx, evaluate, pkg, found, err)
		}
		// Yarn Classic reads a dependency from a host that supports remote
		// archives without cloning it. Failing its capability probe makes it
		// clone the repository and archive the commit locally instead.
		if checkout.Remote != "" {
			return errors.New("supply chain firewall does not allow remote git archives during yarn commands")
		}
		read := func(limit int64) ([]byte, error) {
			return githook.ReadBlob(ctx, checkout.Dir, checkout.SHA+":package.json", limit)
		}
		pkg, found, err := npmregistry.YarnClassicArchivePackage(checkout.Dir, checkout.Origin, checkout.SHA, read)
		return evaluateCheckout(ctx, evaluate, pkg, found, err)
	}
}

func evaluateCheckout(ctx context.Context, evaluate func(context.Context, pm.Package, error) error, pkg pm.Package, found bool, err error) error {
	if err != nil {
		return fmt.Errorf("supply chain firewall could not read the git checkout: %w", err)
	}
	if !found {
		return nil
	}
	if err := evaluate(ctx, pkg, nil); err != nil {
		return fmt.Errorf("%w (%s)", err, pkg.Source)
	}
	return nil
}

// gitHookRunner gives the proxied command git hooks that ask decide about
// each checkout. decide is set while hooks are configured, before the command
// starts.
type gitHookRunner struct {
	pm.ProxyRunner
	executable string
	decide     *githook.Decide
	// archives also asks about git archives, see githook.ApplyArchives.
	archives bool
	hooks    *githook.Hooks
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
	if r.archives {
		if err := r.hooks.ApplyArchives(&spec); err != nil {
			return proxy.CommandSpec{}, err
		}
	}
	return spec, nil
}

// Close removes the hooks once the command has finished.
func (r *gitHookRunner) Close() {
	if r.hooks != nil {
		_ = r.hooks.Close()
	}
}
