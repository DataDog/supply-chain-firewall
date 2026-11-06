// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	all := poetryProxyEnv("all_proxy")
	bypass := os.Getenv("no_proxy")
	if bypass == "" {
		bypass = os.Getenv("NO_PROXY")
	}
	config := httpproxy.Config{HTTPProxy: all, HTTPSProxy: all, NoProxy: bypass}
	if value := poetryProxyEnv("http_proxy"); value != "" {
		config.HTTPProxy = value
	}
	if value := poetryProxyEnv("https_proxy"); value != "" {
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
		if value == "" {
			continue
		}
		parsed, err := url.Parse(poetryProxyURL(value))
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			// Parsing errors may quote credentials from the original URL.
			return httpproxy.Config{}, native, errors.New("unsupported or invalid Poetry upstream proxy URL")
		}
	}
	return config, native, nil
}

func poetryProxyEnv(name string) string {
	if value, present := os.LookupEnv(name); present {
		return value
	}
	// urllib ignores uppercase HTTP_PROXY in CGI environments.
	if name == "http_proxy" && os.Getenv("REQUEST_METHOD") != "" {
		return ""
	}
	return os.Getenv(strings.ToUpper(name))
}

func poetryProxyURL(value string) string {
	if !strings.Contains(value, "://") {
		return "http://" + value
	}
	return value
}

// ProxyOptions preserves the trust used by Requests and Git on the outbound
// side of interception. No Poetry configuration subprocess is needed.
func (poetry Poetry) ProxyOptions(command []string) (proxy.Options, error) {
	upstream, native, err := discoverPoetryProxies(pythonproxy.ReadSystem)
	if err != nil {
		return proxy.Options{}, err
	}
	ca := os.Getenv("REQUESTS_CA_BUNDLE")
	if ca == "" {
		ca = os.Getenv("CURL_CA_BUNDLE")
	}
	paths := []string{ca, os.Getenv("GIT_SSL_CAINFO"), os.Getenv("GIT_SSL_CAPATH"), os.Getenv("SSL_CERT_FILE")}
	paths = append(paths, filepath.SplitList(os.Getenv("SSL_CERT_DIR"))...)
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
		parsed, err := url.Parse(poetryProxyURL(value))
		if err != nil {
			return nil, errors.New("invalid Poetry upstream proxy URL")
		}
		return parsed, nil
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
		}
		// Requests and urllib both compare domain boundaries. urllib's
		// case-insensitive check also applies to literal addresses.
		pattern = strings.ToLower(strings.TrimLeft(pattern, "."))
		if host == pattern || hostPort == pattern || strings.HasSuffix(host, "."+pattern) || strings.HasSuffix(hostPort, "."+pattern) {
			return true
		}
	}
	return false
}

// ProxyCommand changes only the child environment. Poetry keeps control of its
// sources, authentication/keyring, virtualenv, lockfile, cache and arguments;
// the core runner owns streams, signals, exit status and per-invocation cleanup.
func (poetry Poetry) ProxyCommand(_ context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	return proxy.CommandSpec{
		Executable: poetry.Executable(), Args: slices.Clone(command),
		EnvOverrides: map[string]string{
			"http_proxy": config.URL, "HTTP_PROXY": config.URL,
			"https_proxy": config.URL, "HTTPS_PROXY": config.URL,
			"all_proxy": config.URL, "ALL_PROXY": config.URL,
			"no_proxy": "", "NO_PROXY": "",
			"REQUESTS_CA_BUNDLE": config.CACertificatePath,
			"GIT_SSL_CAINFO":     config.CACertificatePath,
			// Poetry's default Dulwich Git client uses Python's SSL roots.
			"SSL_CERT_FILE": config.CACertificatePath,
		},
	}, nil
}

func poetryHasEnvironmentProxies() bool {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasSuffix(strings.ToLower(key), "_proxy") && value != "" {
			values[strings.ToLower(key)] = value
		}
	}
	if os.Getenv("REQUEST_METHOD") != "" {
		delete(values, "http_proxy")
	}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if key == strings.ToLower(key) && strings.HasSuffix(key, "_proxy") {
			if value == "" {
				delete(values, key)
			} else {
				values[key] = value
			}
		}
	}
	return len(values) != 0
}
