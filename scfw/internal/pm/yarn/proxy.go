// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func (yarn Yarn) UpstreamProxy(command []string) (httpproxy.Config, error) {
	gen, err := yarn.generation()
	if err != nil {
		return httpproxy.Config{}, err
	}
	var config httpproxy.Config
	if gen == classic {
		settings, err := yarn.classicSettings(command)
		if err != nil {
			return httpproxy.Config{}, err
		}
		config = httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy}
	} else {
		settings, err := yarn.berrySettings(command)
		if err != nil {
			return httpproxy.Config{}, err
		}
		config = httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP}
	}
	return config, validateUpstream(config)
}

// ProxyOptions transfers Yarn's effective routing and registry trust to the core.
func (yarn Yarn) ProxyOptions(command []string) (proxy.Options, error) {
	upstream, err := yarn.UpstreamProxy(command)
	if err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{Upstream: upstream, ProxyForURL: yarnProxyForURL(upstream)}
	var caFile string
	var pems [][]byte
	var strictSSL bool
	if gen, _ := yarn.generation(); gen == classic {
		settings, err := yarn.classicSettings(command)
		if err != nil {
			return proxy.Options{}, err
		}
		caFile, strictSSL = settings.CAFile, settings.StrictSSL
		for _, ca := range settings.CA {
			pems = append(pems, []byte(ca))
		}
	} else {
		settings, err := yarn.berrySettings(command)
		if err != nil {
			return proxy.Options{}, err
		}
		caFile, strictSSL = settings.CAFile, settings.StrictSSL
	}
	options.TrustURL = yarnTrustURL(strictSSL)
	// Yarn and Node ignore a CA file they cannot read; Git requires
	// GIT_SSL_CAINFO, so a missing bundle fails.
	var paths []string
	for _, path := range []string{caFile, os.Getenv("NODE_EXTRA_CA_CERTS")} {
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

var _ pm.ProxyOptionsProvider = Yarn{}

// yarnProxyForURL routes like Yarn, which proxies loopback hosts too; Go's
// flattened proxy configuration would connect to them directly. NoProxy holds
// the standard variable's entries, matched like Yarn Classic's request client.
func yarnProxyForURL(upstream httpproxy.Config) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value := upstream.HTTPProxy
		if target.Scheme == "https" {
			value = upstream.HTTPSProxy
		}
		if value == "" || noProxyMatches(target, upstream.NoProxy) {
			return nil, nil
		}
		return proxy.ParseUpstreamProxyURL(value)
	}
}

func noProxyMatches(target *url.URL, noProxy string) bool {
	host, port := strings.ToLower(target.Hostname()), target.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[target.Scheme]
	}
	for entry := range strings.SplitSeq(noProxy, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "*" {
			return true
		}
		name, entryPort, hasPort := strings.Cut(entry, ":")
		name = strings.TrimPrefix(name, ".")
		if name != "" && (!hasPort || entryPort == port) && (host == name || strings.HasSuffix(host, "."+name)) {
			return true
		}
	}
	return false
}

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
	if gen == classic {
		return classicProxyCommand(yarn.executable, command, config, pem)
	}
	// Refuse before Yarn starts when its settings would route around SCFW.
	if _, err := yarn.berrySettings(command); err != nil {
		return proxy.CommandSpec{}, err
	}
	return berryProxyCommand(yarn.executable, command, config, pem)
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
