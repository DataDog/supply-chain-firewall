// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

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
	options.UpstreamTLS, err = proxy.NewTLSConfig(pnpmTLSOptions(settings.CAFile, settings.CA, nil))
	if err != nil {
		return proxy.Options{}, err
	}
	if len(settings.RegistryCAs) > 0 {
		options.RouteForRequest = pnpmRegistryRoutes(settings, options.UpstreamTLS)
	}
	return options, nil
}

// pnpmTLSOptions builds pnpm's upstream trust. A readable, non-empty cafile
// or a non-empty ca replaces the default roots, as in npm; an empty ca is
// unset. pnpm, unlike npm, keeps NODE_EXTRA_CA_CERTS additive with a CA file.
// A registryCA, when given, replaces the global CA for its registry. Git
// requires GIT_SSL_CAINFO, so a missing bundle fails.
func pnpmTLSOptions(caFile string, ca []string, registryCA *registryCA) proxy.TLSConfigOptions {
	if registryCA != nil {
		caFile, ca = registryCA.CAFile, nil
		if registryCA.CA != "" {
			ca = []string{registryCA.CA}
		}
	}
	options := proxy.TLSConfigOptions{CABundlePaths: []string{os.Getenv("GIT_SSL_CAINFO")}}
	if data, err := os.ReadFile(caFile); err == nil && len(data) > 0 {
		options.RootCAs = x509.NewCertPool()
		options.CABundlePaths = append(options.CABundlePaths, caFile)
	} else {
		for _, value := range ca {
			if value != "" {
				options.RootCAs = x509.NewCertPool()
				options.CABundlePEM = append(options.CABundlePEM, []byte(value))
			}
		}
	}
	if extra := os.Getenv("NODE_EXTRA_CA_CERTS"); extra != "" {
		// Node ignores an unreadable bundle.
		if _, err := os.Stat(extra); err == nil {
			options.CABundlePaths = append(options.CABundlePaths, extra)
		}
	}
	return options
}

// pnpmRegistryRoutes scopes pnpm's per-registry CA settings to their
// registry: pnpm applies //host/:cafile to that registry in place of the
// global CA, and no other upstream host sees those roots.
func pnpmRegistryRoutes(settings pnpmSettings, base *tls.Config) func(proxy.Request) (*proxy.OutboundRoute, error) {
	proxyForURL := pnpmProxyForURL(settings)
	var mutex sync.Mutex
	routes := map[string]*proxy.OutboundRoute{}
	return func(request proxy.Request) (*proxy.OutboundRoute, error) {
		ca, matched := pnpmRegistryCA(settings.RegistryCAs, &request.URL)
		if !matched {
			return nil, nil
		}
		upstream, err := proxyForURL(&request.URL)
		if err != nil {
			return nil, err
		}
		key := ca.Key
		if upstream != nil {
			key += "|" + upstream.String()
		}
		mutex.Lock()
		defer mutex.Unlock()
		if route := routes[key]; route != nil {
			return route, nil
		}
		tlsConfig, err := proxy.NewTLSConfig(pnpmTLSOptions(settings.CAFile, settings.CA, &ca))
		if err != nil {
			return nil, err
		}
		// A route replaces the core's transports, so pnpm's strict-ssl
		// exception must travel with the registry's own trust.
		tlsConfig.InsecureSkipVerify = !settings.StrictSSL
		route := &proxy.OutboundRoute{ProxyURL: upstream, TLS: tlsConfig}
		if upstream != nil && upstream.Scheme == "https" {
			// A registry's destination trust never reaches an HTTPS proxy,
			// which the base roots verify.
			route.ProxyTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: base.RootCAs}
		}
		routes[key] = route
		return route, nil
	}
}

// pnpmRegistryCA returns the per-registry CA setting that applies to target.
// npm-style keys name a registry host, optionally with a port; a key without a
// port covers the scheme's default port. An inline ca wins over a cafile, as
// in npm.
func pnpmRegistryCA(cas []registryCA, target *url.URL) (registryCA, bool) {
	defaultPort := "80"
	if target.Scheme == "https" {
		defaultPort = "443"
	}
	targetPort := target.Port()
	if targetPort == "" {
		targetPort = defaultPort
	}
	var fallback *registryCA
	for index := range cas {
		scoped := strings.TrimPrefix(cas[index].Key, "//")
		if slash := strings.Index(scoped, "/"); slash >= 0 {
			scoped = scoped[:slash]
		}
		host, port, err := net.SplitHostPort(scoped)
		if err != nil {
			host, port = scoped, ""
		}
		if port == "" {
			port = defaultPort
		}
		if !strings.EqualFold(host, target.Hostname()) || port != targetPort {
			continue
		}
		if cas[index].CA != "" {
			return cas[index], true
		}
		if fallback == nil {
			fallback = &cas[index]
		}
	}
	if fallback == nil {
		return registryCA{}, false
	}
	return *fallback, true
}

var _ pm.ProxyOptionsProvider = Pnpm{}

// noProxySentinel replaces pnpm's noproxy settings with a host that matches
// nothing; pnpm ignores empty values, which would let a lower layer's entry
// send registry traffic around SCFW.
const noProxySentinel = "scfw.invalid"

// ProxyCommand supplies pnpm-specific arguments and environment overrides. The
// core proxy owns process execution, signals, streams, and invocation cleanup.
func (p Pnpm) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	// Refuse before pnpm starts when its settings would route around SCFW.
	settings, err := p.settings(command)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	if err := validateUpstream(settings); err != nil {
		return proxy.CommandSpec{}, err
	}
	major, err := p.major(command)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	pem, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		return proxy.CommandSpec{}, errors.New("read proxy CA certificate")
	}
	ca := config.CACertificatePath
	// Command-line settings beat every configuration layer. They go before the
	// command, where they cannot reach the arguments of dlx, exec, or a script;
	// the user's own proxy and trust options are removed because pnpm applies
	// the last one, or accumulates noproxy values.
	overrides := []string{
		"--config.https-proxy=" + config.URL, "--config.proxy=" + config.URL, "--config.http-proxy=" + config.URL,
		"--config.noproxy=" + noProxySentinel, "--config.no-proxy=" + noProxySentinel,
		"--config.cafile=" + ca, "--config.ca=" + string(pem),
	}
	// pnpm 11 trusts a per-registry CA over the global one, even through a proxy.
	for _, registryCA := range settings.RegistryCAs {
		overrides = append(overrides, "--config."+registryCA.Key+":cafile="+ca)
	}
	parsed := parseCommand(major, p.dlx, command)
	tail, err := withOverrides(major, parsed, overrides)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	args := slices.Concat(overrides, tail)

	extraCAs, err := nodeproxy.NodeExtraCACerts(ca, pem)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	// The variables route nested pnpm and npm processes, which do not inherit
	// the command line; pnpm 10 reads npm_config_* and pnpm 11 and 12 read
	// pnpm_config_*, and a pinned version may be either.
	canonical := config.EnvironmentOverrides()
	maps.Copy(canonical, map[string]string{
		"npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL,
		"npm_config_noproxy": noProxySentinel, "npm_config_no_proxy": noProxySentinel, "npm_config_cafile": ca,
		"pnpm_config_proxy": config.URL, "pnpm_config_http_proxy": config.URL, "pnpm_config_https_proxy": config.URL,
		"pnpm_config_noproxy": noProxySentinel, "pnpm_config_no_proxy": noProxySentinel,
		"pnpm_config_cafile": ca, "pnpm_config_ca": string(pem),
		"NODE_EXTRA_CA_CERTS": extraCAs, "GIT_SSL_CAINFO": ca,
	})
	return proxy.CommandSpec{Executable: p.executable, Args: args, EnvOverrides: nodeproxy.OverrideVariants(os.Environ(), canonical)}, nil
}

var _ pm.ProxyRunner = Pnpm{}

// withOverrides returns parsed's arguments for a pnpm of major. `pnpm with
// <version>` (pnpm 11 and later) runs that release with only the arguments
// after the version, so every nested level gets its own overrides, and its
// command line is parsed as that release reads it.
func withOverrides(major int, parsed parsedCommand, overrides []string) ([]string, error) {
	if major < 11 || parsed.name != "with" || parsed.sub == "current" {
		return parsed.args, nil
	}
	child, err := withMajor(parsed.sub)
	if err != nil {
		return nil, err
	}
	tail, err := withOverrides(child, parseCommand(child, false, parsed.args[parsed.passthrough:]), overrides)
	if err != nil {
		return nil, err
	}
	return slices.Concat(parsed.args[:parsed.passthrough], overrides, tail), nil
}

// withMajor returns the supported major an exact `pnpm with` version selects.
func withMajor(version string) (int, error) {
	major, err := strconv.Atoi(version)
	if parsed, parseErr := pm.ParseVersion(version); err != nil && parseErr == nil {
		major, err = parsed.Major, nil
	}
	if err != nil || major < 10 || major > 12 {
		return 0, errors.New("pnpm with is supported through SCFW only for an exact pnpm 10, 11, or 12 version")
	}
	return major, nil
}

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
