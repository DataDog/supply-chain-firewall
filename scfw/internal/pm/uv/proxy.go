// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/net/http/httpproxy"
)

var (
	_ pm.PackageManager       = UV{}
	_ pm.ProxyRunner          = UV{}
	_ pm.ProxyOptionsProvider = UV{}
	_ pm.ProxyCommandSelector = UV{}
)

// reqwest prefers uppercase variables, with ALL_PROXY as a per-scheme fallback.
// Capture before installing any child-only SCFW overrides. Unlike Go's default
// proxy matcher, uv does not implicitly bypass loopback destinations.
func upstreamSettings(settings map[string]any) (httpproxy.Config, error) {
	config := httpproxy.Config{
		HTTPProxy:  firstEnvironment("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: firstEnvironment("HTTPS_PROXY", "https_proxy"),
		NoProxy:    firstEnvironment("NO_PROXY", "no_proxy"),
	}
	if config.HTTPProxy == "" {
		config.HTTPProxy = firstEnvironment("ALL_PROXY", "all_proxy")
	}
	if config.HTTPSProxy == "" {
		config.HTTPSProxy = firstEnvironment("ALL_PROXY", "all_proxy")
	}
	if _, cgi := os.LookupEnv("REQUEST_METHOD"); cgi {
		config = httpproxy.Config{}
	}
	httpProxy, explicitHTTP := settings["http-proxy"]
	httpsProxy, explicitHTTPS := settings["https-proxy"]
	if explicitHTTP || explicitHTTPS {
		// Adding an explicit reqwest proxy disables automatic environment proxy
		// discovery, including for a scheme with no explicit proxy.
		config.HTTPProxy, _ = httpProxy.(string)
		config.HTTPSProxy, _ = httpsProxy.(string)
		if (explicitHTTP && config.HTTPProxy == "") || (explicitHTTPS && config.HTTPSProxy == "") {
			return httpproxy.Config{}, errors.New("invalid uv proxy configuration")
		}
		config.NoProxy = ""
		if raw, configured := settings["no-proxy"]; configured {
			values, ok := raw.([]any)
			if !ok {
				return httpproxy.Config{}, errors.New("invalid uv proxy bypass configuration")
			}
			for _, value := range values {
				text, ok := value.(string)
				if !ok {
					return httpproxy.Config{}, errors.New("invalid uv proxy bypass configuration")
				}
				config.NoProxy += text + ","
			}
		}
	}
	for _, value := range []string{config.HTTPProxy, config.HTTPSProxy} {
		if _, err := parseProxyURL(value); err != nil {
			return httpproxy.Config{}, err
		}
	}
	return config, nil
}

func firstEnvironment(names ...string) string {
	for _, name := range names {
		if value, present := os.LookupEnv(name); present {
			return value
		}
	}
	return ""
}

func parseProxyURL(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("unsupported or invalid uv upstream proxy URL")
	}
	return parsed, nil
}

func (uv UV) UpstreamProxy(command []string) (httpproxy.Config, error) {
	settings, err := uv.settings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	return upstreamSettings(settings)
}

func (uv UV) ProxyOptions(command []string) (proxy.Options, error) {
	settings, err := uv.settings(command)
	if err != nil {
		return proxy.Options{}, err
	}
	upstream, err := upstreamSettings(settings)
	if err != nil {
		return proxy.Options{}, err
	}
	trust, err := trustURL(settings, parseOptions(command))
	if err != nil {
		return proxy.Options{}, err
	}
	options := proxy.Options{Upstream: upstream, ProxyForURL: proxyForURL(upstream), TrustURL: trust}
	options.UpstreamTLS, err = uvTLSConfig(command)
	if err != nil {
		return proxy.Options{}, err
	}
	// Git is a separate TLS client: its CA settings must not widen uv's roots.
	options.AdditionalClients = map[string]proxy.Options{"git": {
		Upstream: upstream, ProxyForURL: options.ProxyForURL, UpstreamTLS: gitTLSConfig(),
	}}

	return options, nil
}

func proxyForURL(config httpproxy.Config) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		if bypassProxy(target.Hostname(), config.NoProxy) {
			return nil, nil
		}
		if target.Scheme == "https" {
			return parseProxyURL(config.HTTPSProxy)
		}
		return parseProxyURL(config.HTTPProxy)
	}
}

func bypassProxy(host, patterns string) bool {
	ip := net.ParseIP(host)
	for _, pattern := range strings.Split(patterns, ",") {
		pattern = strings.TrimSpace(pattern)
		if ip != nil {
			if parsed := net.ParseIP(pattern); parsed != nil && parsed.Equal(ip) {
				return true
			}
			if _, network, err := net.ParseCIDR(pattern); err == nil && network.Contains(ip) {
				return true
			}
		} else {
			pattern = strings.TrimPrefix(strings.ToLower(pattern), ".")
			host = strings.ToLower(host)
			if pattern == "*" || host == pattern || strings.HasSuffix(host, "."+pattern) {
				return true
			}
		}
	}
	return false
}

// ProxyCommand preserves uv's command and settings, replacing only per-process
// routing and CA inputs. The core owns execution and deletes invocation files.
func (uv UV) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	args := slices.Clone(command)
	for _, option := range parseOptions(command).options {
		if option.name == "cert" {
			args[option.index] = config.CACertificatePath
			if option.equal {
				args[option.index] = "--cert=" + config.CACertificatePath
			}
		}
	}
	gitConfig := config
	if git, exists := config.AdditionalClients["git"]; exists {
		gitConfig = git
	}
	environment := map[string]string{
		"HTTP_PROXY": config.URL, "http_proxy": config.URL,
		"HTTPS_PROXY": config.URL, "https_proxy": config.URL,
		"ALL_PROXY": config.URL, "all_proxy": config.URL,
		"NO_PROXY": "", "no_proxy": "",
		"SSL_CERT_FILE":  config.CACertificatePath,
		"GIT_SSL_CAINFO": gitConfig.CACertificatePath,
	}
	settings, err := uv.settings(command)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	if settings["http-proxy"] != nil || settings["https-proxy"] != nil {
		// uv.toml proxies disable reqwest's environment proxy discovery. Supply
		// the same effective settings with only routing replaced, in the CA's
		// private invocation directory so core cleanup covers this file too.
		settings["http-proxy"], settings["https-proxy"] = config.URL, config.URL
		settings["no-proxy"] = []string{}
		content, err := toml.Marshal(settings)
		if err != nil {
			return proxy.CommandSpec{}, errors.New("could not encode invocation uv configuration")
		}
		path := filepath.Join(filepath.Dir(config.CACertificatePath), "uv.toml")
		if os.WriteFile(path, content, 0600) != nil {
			return proxy.CommandSpec{}, errors.New("could not write invocation uv configuration")
		}
		environment["UV_CONFIG_FILE"] = path
		for _, option := range parseOptions(command).options {
			if option.name == "config-file" {
				args[option.index] = path
				if option.equal {
					args[option.index] = "--config-file=" + path
				}
			}
		}
	}
	// Git's http.proxy configuration outranks standard proxy variables. Append
	// an invocation-only override while retaining existing Git config entries.
	count := 0
	if value := os.Getenv("GIT_CONFIG_COUNT"); value != "" {
		var err error
		count, err = strconv.Atoi(value)
		if err != nil || count < 0 || count > 10000 {
			return proxy.CommandSpec{}, errors.New("invalid Git environment configuration count")
		}
	}
	environment["GIT_CONFIG_COUNT"] = strconv.Itoa(count + 1)
	environment["GIT_CONFIG_KEY_"+strconv.Itoa(count)] = "http.proxy"
	environment["GIT_CONFIG_VALUE_"+strconv.Itoa(count)] = gitConfig.URL
	return proxy.CommandSpec{Executable: uv.executable, Args: args, EnvOverrides: environment}, nil
}
