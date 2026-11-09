// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

var _ pm.ProxyRunner = Npm{}

func upstreamSettings(result npmDiscoveryResult) httpproxy.Config {
	return httpproxy.Config{HTTPProxy: result.HTTP, HTTPSProxy: result.HTTPS, NoProxy: result.NoProxy}
}

func (npm Npm) UpstreamProxy(command []string) (httpproxy.Config, error) {
	settings, err := npm.settings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	return upstreamSettings(settings), validateUpstream(settings)
}

// ProxyOptions transfers npm's effective routing to the core.
func (npm Npm) ProxyOptions(command []string) (proxy.Options, error) {
	settings, err := npm.settings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	if err := validateUpstream(settings); err != nil {
		return proxy.Options{}, err
	}
	return proxy.Options{Upstream: upstreamSettings(settings)}, nil
}

// validateUpstream checks every proxy npm could select. npm parses proxies
// with the WHATWG URL parser, which rejects a value without a scheme.
func validateUpstream(result npmDiscoveryResult) error {
	for _, value := range result.candidates {
		parsed, err := url.Parse(value)
		if err != nil || !strings.Contains(value, "://") || parsed.Hostname() == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("unsupported or invalid npm upstream proxy URL")
		}
	}
	return nil
}

// npmNoProxySentinel replaces npm's noproxy setting with a host that matches
// nothing. npm ignores empty npm_config_* values, so an empty override would
// let a noproxy entry from an .npmrc send registry traffic around SCFW.
const npmNoProxySentinel = "scfw.invalid"

// ProxyCommand supplies npm-specific arguments and environment overrides. The
// core proxy owns process execution, signals, streams, and invocation cleanup.
func (npm Npm) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	pem, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		return proxy.CommandSpec{}, errors.New("read proxy CA certificate")
	}
	args := slices.Clone(command)
	// npm applies the last occurrence of an option, and command-line options
	// take precedence over environment and .npmrc settings. The PEM uses the
	// "=" form because, as a separate argument, it would start with dashes.
	index := slices.Index(args, "--")
	if index < 0 {
		index = len(args)
	}
	args = slices.Insert(args, index,
		"--https-proxy="+config.URL, "--proxy="+config.URL, "--noproxy="+npmNoProxySentinel,
		"--cafile="+config.CACertificatePath, "--ca="+string(pem),
	)
	overrides := proxyEnvironmentOverrides(os.Environ(), config, string(pem))
	// Lifecycle scripts ignore the proxy variables unless NODE_USE_ENV_PROXY is
	// set, so they may still connect directly and need the user's own CAs.
	if userCAs, err := os.ReadFile(os.Getenv("NODE_EXTRA_CA_CERTS")); err == nil {
		bundle := filepath.Join(filepath.Dir(config.CACertificatePath), "node-extra-ca.pem")
		if err := os.WriteFile(bundle, slices.Concat(userCAs, []byte("\n"), pem), 0600); err != nil {
			return proxy.CommandSpec{}, errors.New("write Node CA bundle")
		}
		overrides["NODE_EXTRA_CA_CERTS"] = bundle
	}
	return proxy.CommandSpec{Executable: npm.Executable(), Args: args, EnvOverrides: overrides}, nil
}

// proxyEnvironmentOverrides routes npm, its lifecycle scripts, and Git through
// the proxy. npm reads npm_config_* names case-insensitively and accepts dashes
// for underscores, and npm 7-10 prefer a non-lowercase variant over the
// lowercase one. The core replaces exact keys only, so every variant already
// present in environ receives the same value as its canonical key.
func proxyEnvironmentOverrides(environ []string, config proxy.ClientConfig, caPEM string) map[string]string {
	canonical := map[string]string{
		"http_proxy": config.URL, "HTTP_PROXY": config.URL,
		"https_proxy": config.URL, "HTTPS_PROXY": config.URL,
		"all_proxy": config.URL, "ALL_PROXY": config.URL,
		"no_proxy": "", "NO_PROXY": "",
		"npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL,
		"npm_config_noproxy": npmNoProxySentinel,
		"npm_config_cafile":  config.CACertificatePath, "npm_config_ca": caPEM,
		"NODE_EXTRA_CA_CERTS": config.CACertificatePath, "GIT_SSL_CAINFO": config.CACertificatePath,
	}
	overrides := maps.Clone(canonical)
	for _, item := range environ {
		key, _, _ := strings.Cut(item, "=")
		name := strings.ToLower(key)
		if strings.HasPrefix(name, "npm_config_") {
			name = strings.ReplaceAll(name, "-", "_")
		} else if !strings.HasSuffix(name, "_proxy") {
			continue
		}
		if value, found := canonical[name]; found {
			overrides[key] = value
		}
	}
	return overrides
}
