// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/gitproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
)

var _ pm.ProxyRunner = Pip{}

func upstreamSettings(settings pipDiscoveryResult) httpproxy.Config {
	return httpproxy.Config{HTTPProxy: settings.HTTP, HTTPSProxy: settings.HTTPS, NoProxy: settings.NoProxy}
}

func (pip Pip) UpstreamProxy(command []string) (httpproxy.Config, error) {
	settings, err := pip.settings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	config := upstreamSettings(settings)
	return config, validateUpstream(config)
}

// ProxyOptions transfers pip's effective routing and registry trust to the core.
func (pip Pip) ProxyOptions(command []string) (proxy.Options, error) {
	settings, err := pip.settings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	if err := validateUpstream(upstreamSettings(settings)); err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{Upstream: upstreamSettings(settings), TrustURL: pipTrustURL(settings.TrustedHosts), ProxyForURL: pipProxyForURL(settings), RequestHooks: []proxy.RequestHook{pipHTTPSBypassHook(settings)}}
	options.UpstreamTLS, err = proxy.NewTLSConfig(proxy.TLSConfigOptions{
		CABundlePaths:         []string{expandPipPath(settings.Cert)},
		ClientCertificatePath: expandPipPath(settings.ClientCert),
	})
	if err != nil {
		return proxy.Options{}, err
	}
	git, err := pip.gitSettings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	options.AdditionalClients = git.AdditionalClients()
	options.AdditionalClients["git"] = proxy.Options{RouteForRequest: git.Route}
	return options, nil
}

// ProxyCommand supplies pip-specific arguments and environment overrides. The
// core proxy owns process execution, signals, streams, and invocation cleanup.
func (pip Pip) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	args := slices.Clone(command)
	// CLI options take precedence under --isolated and over original options.
	index := slices.Index(args, "--")
	if index < 0 {
		index = len(args)
	}
	args = slices.Insert(args, index, "--proxy", config.URL, "--cert", config.CACertificatePath)
	overrides := proxyEnvironmentOverrides(config)
	gitConfig := config
	if git, exists := config.AdditionalClients["git"]; exists {
		gitConfig = git
		gitConfig.AdditionalClients = config.AdditionalClients
	}
	git, err := pip.gitSettings(command)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	if err := git.ChildOverrides(overrides, gitConfig); err != nil {
		return proxy.CommandSpec{}, err
	}
	return proxy.CommandSpec{Executable: pip.Executable(), Args: args, EnvOverrides: overrides, EnvRemovals: []string{"GIT_SSL_NO_VERIFY"}}, nil
}

// The same invocation snapshot configures native Git routes and its child overrides.
type pipProxyState struct {
	mutex   sync.Mutex
	command []string
	git     *gitproxy.Settings
}

func (pip Pip) gitSettings(command []string) (*gitproxy.Settings, error) {
	if pip.proxyState != nil {
		pip.proxyState.mutex.Lock()
		defer pip.proxyState.mutex.Unlock()
		if pip.proxyState.git != nil && slices.Equal(command, pip.proxyState.command) {
			return pip.proxyState.git, nil
		}
	}
	directory, err := pip.ProjectDirectory(command)
	if err != nil {
		return nil, err
	}
	settings, err := gitproxy.Read(directory)
	if err != nil {
		return nil, err
	}
	if pip.proxyState != nil {
		pip.proxyState.command, pip.proxyState.git = slices.Clone(command), settings
	}
	return settings, nil
}

func proxyEnvironmentOverrides(config proxy.ClientConfig) map[string]string {
	environment := config.EnvironmentOverrides()
	for key, value := range map[string]string{
		"PIP_PROXY": config.URL,
		"PIP_CERT":  config.CACertificatePath, "REQUESTS_CA_BUNDLE": config.CACertificatePath,
		"CURL_CA_BUNDLE": config.CACertificatePath, "GIT_SSL_CAINFO": config.CACertificatePath,
	} {
		environment[key] = value
	}
	return environment
}

func validateUpstream(config httpproxy.Config) error {
	for _, value := range []string{config.HTTPProxy, config.HTTPSProxy} {
		if _, err := proxy.ParseUpstreamProxyURL(value); err != nil {
			return err
		}
	}
	return nil
}

// requests applies NO_PROXY to environment proxies, then falls back to pip's
// explicit session proxy. In particular, older pip retains that fallback even
// when NO_PROXY matches, unlike one flattened httpproxy configuration.
func pipProxyForURL(settings pipDiscoveryResult) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value, fallback := settings.HTTP, settings.FallbackHTTP
		if target.Scheme == "https" {
			value, fallback = settings.HTTPS, settings.FallbackHTTPS
		}
		if pipBypassesEnvironment(target, settings.RequestsNoProxy, settings.NoProxy, settings.LooseNoProxy) ||
			(settings.SystemProxyBypass != nil && settings.SystemProxyBypass(target)) {
			value = fallback
		}
		return proxy.ParseUpstreamProxyURL(value)
	}
}

func pipBypassesEnvironment(target *url.URL, requestsNoProxy, noProxy string, loose bool) bool {
	host := strings.ToLower(target.Hostname())
	hostPort := host
	if target.Port() != "" {
		hostPort += ":" + target.Port()
	}
	ip := net.ParseIP(host)
	// Requests first applies its own matcher, which changed from suffix matching
	// to domain boundaries in newer versions. Then urllib applies its case-
	// insensitive domain matcher; only the entire value "*" is a wildcard.
	for _, pattern := range strings.Split(strings.ReplaceAll(requestsNoProxy, " ", ""), ",") {
		if pattern == "" {
			continue
		}
		if ip != nil && ip.To4() != nil {
			if host == pattern {
				return true
			}
			if _, network, err := net.ParseCIDR(pattern); err == nil {
				ones, bits := network.Mask.Size()
				if bits == 32 && ones > 0 && network.Contains(ip) {
					return true
				}
			}
		} else if loose {
			if strings.HasSuffix(host, pattern) || strings.HasSuffix(hostPort, pattern) {
				return true
			}
		} else {
			pattern = strings.TrimLeft(pattern, ".")
			if host == pattern || hostPort == pattern || strings.HasSuffix(host, "."+pattern) || strings.HasSuffix(hostPort, "."+pattern) {
				return true
			}
		}
	}
	if noProxy == "*" {
		return true
	}
	hostOnly := host
	if index := strings.LastIndexByte(host, ':'); index >= 0 && strings.Trim(host[index+1:], "0123456789") == "" {
		hostOnly = host[:index]
	}
	for _, pattern := range strings.Split(noProxy, ",") {
		pattern = strings.ToLower(strings.TrimLeft(strings.TrimSpace(pattern), "."))
		if pattern != "" && (host == pattern || hostOnly == pattern || strings.HasSuffix(host, "."+pattern) || strings.HasSuffix(hostOnly, "."+pattern)) {
			return true
		}
	}
	return false
}
