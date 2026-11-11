// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"errors"
	"os"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func (yarn Yarn) UpstreamProxy(command []string) (httpproxy.Config, error) {
	gen, err := yarn.generation()
	if err != nil {
		return httpproxy.Config{}, err
	}
	if gen != classic {
		return httpproxy.Config{}, nil
	}
	settings, err := yarn.classicSettings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	config := httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy}
	return config, validateUpstream(config)
}

// ProxyOptions transfers Yarn's effective routing and registry trust to the core.
func (yarn Yarn) ProxyOptions(command []string) (proxy.Options, error) {
	upstream, err := yarn.UpstreamProxy(command)
	if err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{Upstream: upstream}
	if gen, _ := yarn.generation(); gen != classic {
		return options, nil
	}
	settings, err := yarn.classicSettings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	options.TrustURL = yarnTrustURL(settings.StrictSSL)
	// Yarn and Node ignore a CA file they cannot read; Git requires
	// GIT_SSL_CAINFO, so a missing bundle fails.
	var paths []string
	for _, path := range []string{settings.CAFile, os.Getenv("NODE_EXTRA_CA_CERTS")} {
		if _, err := os.Stat(path); path != "" && err == nil {
			paths = append(paths, path)
		}
	}
	var pems [][]byte
	for _, ca := range settings.CA {
		pems = append(pems, []byte(ca))
	}
	options.UpstreamTLS, err = proxy.NewTLSConfig(proxy.TLSConfigOptions{
		CABundlePaths: append(paths, os.Getenv("GIT_SSL_CAINFO")),
		CABundlePEM:   pems,
	})
	return options, err
}

var _ pm.ProxyOptionsProvider = Yarn{}

// ProxyCommand supplies Yarn-specific arguments and environment overrides. The
// core proxy owns process execution, signals, streams, and invocation cleanup.
func (yarn Yarn) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	gen, err := yarn.generation()
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	pem, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		return proxy.CommandSpec{}, errors.New("read proxy CA certificate")
	}
	if gen != classic {
		return proxy.CommandSpec{}, errors.New("yarn berry is not supported yet")
	}
	return classicProxyCommand(yarn.executable, command, config, pem)
}

var _ pm.ProxyRunner = Yarn{}

// validateUpstream rejects proxies the core cannot use, without echoing a URL
// that may carry credentials.
func validateUpstream(config httpproxy.Config) error {
	for _, value := range []string{config.HTTPSProxy, config.HTTPProxy} {
		if _, err := proxy.ParseUpstreamProxyURL(value); err != nil {
			return errors.New("unsupported or invalid yarn upstream proxy URL")
		}
	}
	return nil
}
