// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
)

var _ pm.ProxyRunner = Poetry{}

var _ pm.ProxyOptionsProvider = Poetry{}

// UpstreamProxy captures Requests' environment before the child is pointed at
// SCFW. Lowercase variables take precedence, including an explicitly empty one.
// ALL_PROXY supplies the fallback for either missing protocol-specific proxy.
func (poetry Poetry) UpstreamProxy(_ []string) (httpproxy.Config, error) {
	config, _, err := discoverPoetryProxies(pythonproxy.ReadSystem)
	return config, err
}

func discoverPoetryProxies(readSystem func() (pythonproxy.Settings, error)) (httpproxy.Config, pythonproxy.Settings, error) {
	environment := pythonproxy.Environment()
	all := environment["all"]
	bypass := os.Getenv("no_proxy")
	if bypass == "" {
		bypass = os.Getenv("NO_PROXY")
	}
	config := httpproxy.Config{HTTPProxy: all, HTTPSProxy: all, NoProxy: bypass}
	if value := environment["http"]; value != "" {
		config.HTTPProxy = value
	}
	if value := environment["https"]; value != "" {
		config.HTTPSProxy = value
	}
	var native pythonproxy.Settings
	if !poetryHasEnvironmentProxies() {
		var err error
		native, err = readSystem()
		if err != nil {
			return config, native, err
		}
		config.HTTPProxy = native.Proxies["http"]
		config.HTTPSProxy = native.Proxies["https"]
	}
	for _, value := range []string{config.HTTPProxy, config.HTTPSProxy} {
		if _, err := proxy.ParseUpstreamProxyURL(value); err != nil {
			return httpproxy.Config{}, native, err
		}
	}
	return config, native, nil
}

func (poetry Poetry) ProxyOptions(command []string) (proxy.Options, error) {
	if err := poetry.checkVersion(); err != nil {
		return proxy.Options{}, err
	}
	upstream, native, err := discoverPoetryProxies(pythonproxy.ReadSystem)
	if err != nil {
		return proxy.Options{}, err
	}
	ca := os.Getenv("REQUESTS_CA_BUNDLE")
	if ca == "" {
		ca = os.Getenv("CURL_CA_BUNDLE")
	}
	paths := []string{ca}
	tlsConfig, err := proxy.NewTLSConfig(proxy.TLSConfigOptions{CABundlePaths: paths})
	route := poetryProxyForURL(upstream)
	return proxy.Options{Upstream: upstream, UpstreamTLS: tlsConfig, ProxyForURL: func(target *url.URL) (*url.URL, error) {
		if native.Bypasses(target) {
			return nil, nil
		}
		return route(target)
	}}, err
}

// Requests does not implicitly bypass loopback as Go's httpproxy does. Keep
// bypass decisions on the outbound side so NO_PROXY never avoids inspection.
func poetryProxyForURL(config httpproxy.Config) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value := config.HTTPProxy
		if target.Scheme == "https" {
			value = config.HTTPSProxy
		}
		if value == "" || poetryBypassesProxy(target, config.NoProxy) {
			return nil, nil
		}
		return proxy.ParseUpstreamProxyURL(value)
	}
}

func poetryBypassesProxy(target *url.URL, noProxy string) bool {
	if noProxy == "*" {
		return true
	}
	host := strings.ToLower(target.Hostname())
	ip := net.ParseIP(host)
	hostPort := host
	if target.Port() != "" {
		hostPort += ":" + target.Port()
	}
	for _, pattern := range strings.Split(strings.ReplaceAll(noProxy, " ", ""), ",") {
		if pattern == "" {
			continue
		}
		ipv4 := ip != nil && ip.To4() != nil && !strings.Contains(host, ":")
		if ipv4 {
			if host == pattern {
				return true
			}
			if _, network, err := net.ParseCIDR(pattern); err == nil {
				ones, bits := network.Mask.Size()
				if bits == 32 && ones > 0 && network.Contains(ip) {
					return true
				}
			}
		}
		// Requests handles domain ports case sensitively, then asks urllib
		// about the hostname only. IPv4 addresses use only this latter fallback.
		literal := strings.TrimLeft(pattern, ".")
		if !ipv4 && (host == literal || hostPort == literal || strings.HasSuffix(host, "."+literal) || strings.HasSuffix(hostPort, "."+literal)) {
			return true
		}
		pattern = strings.ToLower(strings.TrimLeft(strings.TrimSpace(pattern), "."))
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			return true
		}
	}
	return false
}

// ProxyCommand changes only the child environment. Poetry keeps control of its
// sources, authentication/keyring, virtualenv, lockfile, cache and arguments;
// the core runner owns streams, signals, exit status and per-invocation cleanup.
func (poetry Poetry) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	if err := poetry.checkVersion(); err != nil {
		return proxy.CommandSpec{}, err
	}
	spec := proxy.CommandSpec{
		Executable: poetry.Executable(), Args: slices.Clone(command),
		EnvOverrides: config.EnvironmentOverrides(),
	}
	spec.EnvOverrides["REQUESTS_CA_BUNDLE"] = config.CACertificatePath
	spec.EnvOverrides["GIT_SSL_CAINFO"] = config.CACertificatePath
	// Poetry's bundled Dulwich Git client uses Python's SSL roots.
	spec.EnvOverrides["SSL_CERT_FILE"] = config.CACertificatePath
	return spec, nil
}

func poetryHasEnvironmentProxies() bool { return len(pythonproxy.Environment()) != 0 }
