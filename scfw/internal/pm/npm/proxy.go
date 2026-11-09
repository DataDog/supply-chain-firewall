// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

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
	return proxy.CommandSpec{
		Executable:   npm.Executable(),
		Args:         args,
		EnvOverrides: proxyEnvironmentOverrides(os.Environ(), config, string(pem)),
	}, nil
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
