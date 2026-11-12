// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"errors"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func upstreamConfig(settings pnpmSettings) httpproxy.Config {
	config := httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy}
	if settings.NoProxyAll {
		config.NoProxy = "*"
	}
	return config
}

func (p Pnpm) UpstreamProxy(command []string) (httpproxy.Config, error) {
	settings, err := p.settings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	return upstreamConfig(settings), validateUpstream(settings)
}

// ProxyOptions transfers pnpm's effective routing and registry trust to the core.
func (p Pnpm) ProxyOptions(command []string) (proxy.Options, error) {
	settings, err := p.settings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	if err := validateUpstream(settings); err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{
		Upstream:    upstreamConfig(settings),
		ProxyForURL: pnpmProxyForURL(settings),
		TrustURL:    pnpmTrustURL(settings.StrictSSL),
	}
	// pnpm and Node ignore a CA file they cannot read; Git requires
	// GIT_SSL_CAINFO, so a missing bundle fails.
	candidates := []string{settings.CAFile}
	pems := make([][]byte, 0, len(settings.CA))
	for _, ca := range settings.CA {
		pems = append(pems, []byte(ca))
	}
	for _, registryCA := range settings.RegistryCAs {
		candidates = append(candidates, registryCA.CAFile)
		if registryCA.CA != "" {
			pems = append(pems, []byte(registryCA.CA))
		}
	}
	var paths []string
	for _, path := range append(candidates, os.Getenv("NODE_EXTRA_CA_CERTS")) {
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

var _ pm.ProxyOptionsProvider = Pnpm{}

// pnpmProxyForURL applies pnpm's proxy selection and noproxy matching, which
// differ from a flattened httpproxy configuration.
func pnpmProxyForURL(settings pnpmSettings) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value := settings.HTTP
		if target.Scheme == "https" {
			value = settings.HTTPS
		}
		if value == "" || settings.NoProxyAll || nodeproxy.Bypasses(target, settings.NoProxy) {
			return nil, nil
		}
		return proxy.ParseUpstreamProxyURL(value)
	}
}

// validateUpstream rejects the proxies pnpm selects when the core cannot use
// them, without echoing a URL that may carry credentials. pnpm would connect
// directly for an unsupported scheme; SCFW fails instead.
func validateUpstream(settings pnpmSettings) error {
	for _, value := range []string{settings.HTTPS, settings.HTTP} {
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || !strings.Contains(value, "://") || parsed.Hostname() == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("unsupported or invalid pnpm upstream proxy URL")
		}
	}
	return nil
}
