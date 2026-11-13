// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"context"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func (b Bun) UpstreamProxy(command []string) (httpproxy.Config, error) {
	settings, _, err := b.settings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	return httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy}, validateUpstream(settings)
}

// ProxyOptions transfers Bun's upstream routing and registry trust to the core.
func (b Bun) ProxyOptions(command []string) (proxy.Options, error) {
	settings, _, err := b.settings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	if err := validateUpstream(settings); err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{
		Upstream:    httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy},
		ProxyForURL: bunProxyForURL(settings),
	}
	pems := make([][]byte, 0, len(settings.CA))
	for _, ca := range settings.CA {
		pems = append(pems, []byte(ca))
	}
	// Bun ignores a CA file it cannot read; Git requires GIT_SSL_CAINFO, so a
	// missing bundle fails.
	var paths []string
	for _, path := range append(settings.CAFiles, os.Getenv("NODE_EXTRA_CA_CERTS")) {
		if _, err := os.Stat(path); path != "" && err == nil {
			paths = append(paths, path)
		}
	}
	options.UpstreamTLS, err = proxy.NewTLSConfig(proxy.TLSConfigOptions{
		CABundlePaths: append(paths, os.Getenv("GIT_SSL_CAINFO")),
		CABundlePEM:   pems,
	})
	return options, err
}

var _ pm.ProxyOptionsProvider = Bun{}

// noProxySentinel replaces NO_PROXY with a host that matches nothing, so a
// value from a project .env that Bun loads cannot fill in an empty one.
const noProxySentinel = "scfw.invalid"

// ProxyCommand points Bun at the proxy through its environment and, for
// package commands, --cafile after the subcommand: Bun 1.4 lets a configured
// cafile replace NODE_EXTRA_CA_CERTS, and Bun 1.2 and 1.3 ignore --cafile
// through a proxy, so both are set. Before the subcommand, --cafile would make
// Bun run the next argument as a script. The core proxy owns process
// execution, signals, streams, and invocation cleanup.
func (b Bun) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	if err := b.checkVersion(); err != nil {
		return proxy.CommandSpec{}, err
	}
	settings, parsed, err := b.settings(command)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	if err := validateUpstream(settings); err != nil {
		return proxy.CommandSpec{}, err
	}
	pem, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		return proxy.CommandSpec{}, errors.New("read proxy CA certificate")
	}
	ca := config.CACertificatePath
	args := command
	if parsed.insert >= 0 {
		args = slices.Concat(parsed.args[:parsed.insert], []string{"--cafile=" + ca}, parsed.args[parsed.insert:])
	}
	extraCAs, err := nodeproxy.NodeExtraCACerts(ca, pem)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	canonical := config.EnvironmentOverrides()
	canonical["NO_PROXY"], canonical["no_proxy"] = noProxySentinel, noProxySentinel
	canonical["NODE_EXTRA_CA_CERTS"], canonical["GIT_SSL_CAINFO"] = extraCAs, ca
	return proxy.CommandSpec{Executable: b.executable, Args: args, EnvOverrides: nodeproxy.OverrideVariants(os.Environ(), canonical)}, nil
}

var _ pm.ProxyRunner = Bun{}

// bunProxyForURL selects the upstream proxy by scheme with npm-style NO_PROXY
// matching, where "*" bypasses every host.
func bunProxyForURL(settings bunSettings) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value := settings.HTTP
		if target.Scheme == "https" {
			value = settings.HTTPS
		}
		if value == "" || strings.TrimSpace(settings.NoProxy) == "*" || nodeproxy.Bypasses(target, settings.NoProxy) {
			return nil, nil
		}
		return proxy.ParseUpstreamProxyURL(value)
	}
}

// validateUpstream rejects proxies the core cannot use without echoing a URL
// that may carry credentials.
func validateUpstream(settings bunSettings) error {
	for _, value := range []string{settings.HTTPS, settings.HTTP} {
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || !strings.Contains(value, "://") || parsed.Hostname() == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("unsupported or invalid bun upstream proxy URL")
		}
	}
	return nil
}
