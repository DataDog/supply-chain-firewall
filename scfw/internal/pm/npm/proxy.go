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
	"slices"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
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

// ProxyOptions transfers npm's effective routing and registry trust to the core.
func (npm Npm) ProxyOptions(command []string) (proxy.Options, error) {
	settings, err := npm.settings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	if err := validateUpstream(settings); err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{
		Upstream:    upstreamSettings(settings),
		ProxyForURL: npmProxyForURL(settings),
		TrustURL:    npmTrustURL(settings.StrictSSL),
	}
	// npm ignores a cafile it cannot read and Node ignores an unreadable
	// NODE_EXTRA_CA_CERTS; Git requires GIT_SSL_CAINFO, so a missing bundle fails.
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

var _ pm.ProxyOptionsProvider = Npm{}

// npmProxyForURL applies npm's proxy and noproxy rules, which differ from the
// matching of a flattened httpproxy configuration.
func npmProxyForURL(result npmDiscoveryResult) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value := result.HTTP
		if target.Scheme == "https" {
			value = result.HTTPS
		}
		if value == "" || npmBypasses(target, result.NoProxy) {
			return nil, nil
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return nil, errors.New("invalid npm upstream proxy URL")
		}
		return parsed, nil
	}
}

// npmBypasses mirrors @npmcli/agent: an entry matches when its non-empty dot
// segments equal the host's, compared from the right. There is no wildcard,
// matching is case-sensitive, and an entry with a port never matches.
func npmBypasses(target *url.URL, noProxy string) bool {
	host := strings.Split(target.Hostname(), ".")
	slices.Reverse(host)
	for entry := range strings.SplitSeq(noProxy, ",") {
		var segments []string
		for segment := range strings.SplitSeq(strings.TrimSpace(entry), ".") {
			if segment != "" {
				segments = append(segments, segment)
			}
		}
		if len(segments) == 0 || len(segments) > len(host) {
			continue
		}
		slices.Reverse(segments)
		if slices.Equal(host[:len(segments)], segments) {
			return true
		}
	}
	return false
}

// validateUpstream checks the proxies npm selects; npm never parses the
// variables it does not select. npm parses proxies with the WHATWG URL
// parser, which rejects a value without a scheme.
func validateUpstream(result npmDiscoveryResult) error {
	for _, value := range []string{result.HTTPS, result.HTTP} {
		if value == "" {
			continue
		}
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
	args := withoutNoproxyOptions(command)
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
	if overrides["NODE_EXTRA_CA_CERTS"], err = nodeproxy.NodeExtraCACerts(config.CACertificatePath, pem); err != nil {
		return proxy.CommandSpec{}, err
	}
	return proxy.CommandSpec{Executable: npm.Executable(), Args: args, EnvOverrides: overrides}, nil
}

// withoutNoproxyOptions removes the user's --noproxy options before "--".
// npm accumulates repeated --noproxy values instead of keeping the last one,
// so SCFW's sentinel cannot replace them, and a listed host would bypass the
// proxy. npm also expands unambiguous abbreviations, from "--nop" onwards.
// The user's entries still apply to SCFW's own upstream connections.
func withoutNoproxyOptions(command []string) []string {
	args := make([]string, 0, len(command))
	for index := 0; index < len(command); index++ {
		argument := command[index]
		if argument == "--" {
			return append(args, command[index:]...)
		}
		name, _, assigned := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		if !strings.HasPrefix(argument, "--") || len(name) < len("nop") || !strings.HasPrefix("noproxy", name) {
			args = append(args, argument)
			continue
		}
		if !assigned {
			index++
		}
	}
	return args
}

// proxyEnvironmentOverrides routes npm, its lifecycle scripts, and Git through
// the proxy. npm reads npm_config_* names case-insensitively and accepts dashes
// for underscores, and npm 7-10 prefer a non-lowercase variant over the
// lowercase one. The core replaces exact keys only, so every variant already
// present in environ receives the same value as its canonical key.
func proxyEnvironmentOverrides(environ []string, config proxy.ClientConfig, caPEM string) map[string]string {
	canonical := config.EnvironmentOverrides()
	maps.Copy(canonical, map[string]string{
		"npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL,
		"npm_config_noproxy": npmNoProxySentinel,
		"npm_config_cafile":  config.CACertificatePath, "npm_config_ca": caPEM,
		"NODE_EXTRA_CA_CERTS": config.CACertificatePath, "GIT_SSL_CAINFO": config.CACertificatePath,
	})
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
