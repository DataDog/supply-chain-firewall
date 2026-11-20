// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"crypto/x509"
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
	options := proxy.Options{Upstream: upstream, ProxyForURL: yarnProxyForURL(upstream, false, false)}
	var caFile string
	var pems [][]byte
	var strictSSL bool
	if gen, _ := yarn.generation(); gen == classic {
		settings, err := yarn.classicSettings(command)
		if err != nil {
			return proxy.Options{}, err
		}
		caFile, strictSSL = settings.CAFile, settings.StrictSSL
		options.ProxyForURL = yarnProxyForURL(upstream, settings.NoProxyHTTP, settings.NoProxyHTTPS)
		// Yarn keeps ca only when it cannot read cafile.
		if _, err := os.ReadFile(caFile); err != nil {
			caFile = ""
			for _, ca := range settings.CA {
				if ca != "" {
					pems = append(pems, []byte(ca))
				}
			}
		}
	} else {
		settings, err := yarn.berrySettings(command)
		if err != nil {
			return proxy.Options{}, err
		}
		strictSSL = settings.StrictSSL
		// httpsCaFilePath replaces the roots from Yarn 4.9.2, and at any
		// version without an httpsProxy; an earlier proxied Yarn keeps
		// Node's roots.
		if settings.HTTPS == "" || !yarn.version.LessThan(pm.Version{Major: 4, Minor: 9, Patch: 2}) {
			caFile = settings.CAFile
		}
	}
	options.TrustURL = yarnTrustURL(strictSSL)
	// A CA file or inline ca replaces the roots, as in the running Yarn, and
	// Node then ignores NODE_EXTRA_CA_CERTS. Git requires GIT_SSL_CAINFO, so
	// a missing bundle fails, and it is always added.
	tlsOptions := proxy.TLSConfigOptions{CABundlePaths: []string{os.Getenv("GIT_SSL_CAINFO")}}
	if caFile != "" {
		tlsOptions.RootCAs = x509.NewCertPool()
		tlsOptions.CABundlePaths = append(tlsOptions.CABundlePaths, caFile)
	} else if len(pems) > 0 {
		tlsOptions.RootCAs = x509.NewCertPool()
		tlsOptions.CABundlePEM = pems
	} else if extra := os.Getenv("NODE_EXTRA_CA_CERTS"); extra != "" {
		// Node ignores an unreadable bundle.
		if _, err := os.Stat(extra); err == nil {
			tlsOptions.CABundlePaths = append(tlsOptions.CABundlePaths, extra)
		}
	}
	options.UpstreamTLS, err = proxy.NewTLSConfig(tlsOptions)
	return options, err
}

var _ pm.ProxyOptionsProvider = Yarn{}

// yarnProxyForURL routes like Yarn, which proxies loopback hosts too; Go's
// flattened proxy configuration would connect to them directly. NoProxy holds
// the standard variable's entries, matched like Yarn Classic's request client,
// and bypasses a scheme only when its proxy came from the environment.
func yarnProxyForURL(upstream httpproxy.Config, bypassHTTP, bypassHTTPS bool) func(*url.URL) (*url.URL, error) {
	return func(target *url.URL) (*url.URL, error) {
		value, bypass := upstream.HTTPProxy, bypassHTTP
		if target.Scheme == "https" {
			value, bypass = upstream.HTTPSProxy, bypassHTTPS
		}
		if value == "" || bypass && noProxyMatches(target, upstream.NoProxy) {
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
