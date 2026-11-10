// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type poetryProxyState struct {
	mutex    sync.Mutex
	command  []string
	prepared *poetryProxySettings
}

type poetryCertificateRoute struct {
	source  poetrySource
	address *url.URL
	tls     *tls.Config
	err     error
}

var errPoetrySourceURL = errors.New("invalid Poetry source URL")

func (r poetryCertificateRoute) hasHost() bool {
	return r.address != nil && r.address.Host != ""
}

type poetryProxySettings struct {
	settings            poetrySettings
	upstream            poetryProxyConfiguration
	system              pythonproxy.Settings
	registryTLS         *tls.Config
	registryErr         error
	proxyTLS            *tls.Config
	certificates        []poetryCertificateRoute
	identityIndices     []int
	ambiguousIdentities map[int]bool
	identityWarning     sync.Once
	redirectWarning     sync.Once
	modernPaths         bool
	mutex               sync.Mutex
	routes              map[string]*proxy.OutboundRoute
}

func (poetry Poetry) prepareProxy(command []string) (*poetryProxySettings, error) {
	if err := poetry.checkVersion(); err != nil {
		return nil, err
	}
	if poetry.proxyState != nil {
		poetry.proxyState.mutex.Lock()
		defer poetry.proxyState.mutex.Unlock()
		if poetry.proxyState.prepared != nil && slices.Equal(poetry.proxyState.command, command) {
			return poetry.proxyState.prepared, nil
		}
	}
	settings, err := readPoetrySettings(command)
	if err != nil {
		return nil, err
	}

	prepared := &poetryProxySettings{settings: settings, routes: map[string]*proxy.OutboundRoute{}, modernPaths: !poetry.version.LessThan(pm.Version{Major: 2, Minor: 5})}
	prepared.upstream, prepared.system, err = discoverPoetryProxies(pythonproxy.ReadSystem)
	if err != nil {
		return nil, err
	}
	bundle := os.Getenv("REQUESTS_CA_BUNDLE")
	if bundle == "" {
		bundle = os.Getenv("CURL_CA_BUNDLE")
	}
	bundle = settings.workingPath(bundle)
	prepared.registryTLS, err = proxy.NewTLSConfig(poetryTLSOptions(bundle, ""))
	if err != nil {
		prepared.registryErr = err
		prepared.registryTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}
	}
	prepared.proxyTLS = prepared.registryTLS.Clone()
	sources := slices.Clone(settings.sources)
	hasPrimary, hasPyPI := false, false
	for _, source := range sources {
		hasPrimary = hasPrimary || strings.EqualFold(source.Priority, "primary")
		hasPyPI = hasPyPI || strings.EqualFold(source.Name, "pypi")
	}
	if !hasPrimary && !hasPyPI {
		sources = append(sources, poetrySource{Name: "PyPI", URL: "https://pypi.org/simple/"})
	}
	for index := range sources {
		if strings.EqualFold(sources[index].Name, "pypi") {
			sources[index].Name = "PyPI"
			sources[index].URL = "https://pypi.org/"
		}
	}
	// Direct downloads use a global authenticator. Index authenticators use
	// project settings and register their own source without modifying the
	// global authenticator. Retain every origin/configuration context: one
	// shared environment identity is valid only for equivalent policies.
	type configuredSource struct {
		source   poetrySource
		settings poetrySettings
	}
	var configured []configuredSource
	if settings.global != nil {
		for _, source := range settings.global.configuredRepositories() {
			configured = append(configured, configuredSource{source, *settings.global})
		}
	}
	for _, source := range append(settings.configuredRepositories(), sources...) {
		configured = append(configured, configuredSource{source, settings})
	}
	for _, context := range configured {
		source, sourceSettings := context.source, context.settings
		address, err := url.Parse(source.URL)
		if err != nil || address.Host == "" {
			prepared.certificates = append(prepared.certificates, poetryCertificateRoute{source: source, address: address, err: errPoetrySourceURL})
			continue
		}
		cert := sourceSettings.get("certificates", source.Name, "cert")
		verify := sourceSettings.get("certificates", source.Name, "verify")
		if verify == nil {
			verify = cert
		}
		path, enabled := "", true
		switch value := verify.(type) {
		case bool:
			enabled = value
		case string:
			// Poetry converts even an empty string to a Path (the working
			// directory), rather than falling back to the shadowed cert key.
			if value == "" {
				value = "."
			}
			path = sourceSettings.certificatePath(value)
		}

		if path == "" && enabled {
			path = bundle
		}
		clientCertificate := sourceSettings.certificatePath(sourceSettings.get("certificates", source.Name, "client-cert"))
		options := poetryTLSOptions(path, clientCertificate)
		if path == "" && enabled {
			if prepared.registryErr != nil {
				prepared.certificates = append(prepared.certificates, poetryCertificateRoute{source: source, address: address, err: prepared.registryErr})
				continue
			}
			options.RootCAs = prepared.registryTLS.RootCAs
		}
		tlsConfig, err := proxy.NewTLSConfig(options)
		if err != nil {
			prepared.certificates = append(prepared.certificates, poetryCertificateRoute{source: source, address: address, err: err})
			continue
		}
		tlsConfig.InsecureSkipVerify = !enabled // Explicit, source-scoped Poetry verification setting.
		prepared.certificates = append(prepared.certificates, poetryCertificateRoute{source: source, address: address, tls: tlsConfig})
	}
	prepared.prepareIdentities()
	if poetry.proxyState != nil {
		poetry.proxyState.command = slices.Clone(command)
		poetry.proxyState.prepared = prepared
	}
	return prepared, nil
}

func poetryTLSOptions(path, clientCertificate string) proxy.TLSConfigOptions {
	options := proxy.TLSConfigOptions{CABundlePaths: []string{path}, ClientCertificatePath: clientCertificate}
	if path != "" {
		// Explicit Requests bundles replace the default system roots.
		options.RootCAs = x509.NewCertPool()
	}
	return options
}

func poetryHasEnvironmentProxies() bool { return len(pythonproxy.Environment()) != 0 }

func (s *poetryProxySettings) route(request proxy.Request) (*proxy.OutboundRoute, error) {
	return s.requestsRoute(request)
}

func (s *poetryProxySettings) requestsRoute(request proxy.Request) (*proxy.OutboundRoute, error) {
	upstream, err := s.upstreamProxy(&request.URL)
	if err != nil {
		return nil, err
	}
	source := -1
	best, contained := -1, false
	for i, configured := range s.certificates {
		if !configured.hasHost() || !strings.EqualFold(request.URL.Host, configured.address.Host) || (configured.address.Scheme == "https" && request.URL.Scheme != "https") {
			continue
		}
		score, inside := poetrySourceMatch(configured.address.Path, request.URL.Path, s.modernPaths)
		if source < 0 || score > best || (score == best && inside && !contained) {
			source, best, contained = i, score, inside
		}
	}
	if identity, ok := strings.CutPrefix(request.ClientIdentity, "poetry-source-"); ok {
		index, err := strconv.Atoi(identity)
		if err != nil || index < 0 || index >= len(s.certificates) {
			return nil, errors.New("invalid Poetry TLS client identity")
		}
		if s.ambiguousIdentities[index] {
			return nil, s.identityCompatibilityError()
		}
		source = index
		// Requests retains an existing scheme proxy through rebuild_proxies,
		// even when the redirected destination is covered by NO_PROXY.
		initialProxy, err := s.sourceProxy(index, request.URL.Scheme)
		if err != nil {
			return nil, err
		}
		if initialProxy != nil {
			upstream = initialProxy
		}
	} else if request.ClientIdentity == "poetry-default" && request.URL.Scheme == "https" {
		// An unconfigured-origin Requests call retains cert=None and its
		// default verify setting across redirects into configured repositories.
		source = -1
	}
	needsTLS := request.URL.Scheme == "https" || (upstream != nil && upstream.Scheme == "https")
	if needsTLS && source >= 0 && s.ambiguousIdentities[s.identityIndices[source]] {
		return nil, s.identityCompatibilityError()
	}
	tlsConfig := s.registryTLS
	if source >= 0 {
		if needsTLS && s.certificates[source].err != nil {
			return nil, s.certificates[source].err
		}
		if s.certificates[source].tls != nil {
			tlsConfig = s.certificates[source].tls
		}
	} else if needsTLS && s.registryErr != nil {
		return nil, s.registryErr
	}
	key := request.URL.Scheme + "/" + strconv.Itoa(source)
	if upstream != nil {
		key += "/" + upstream.String()
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if existing := s.routes[key]; existing != nil {
		return existing, nil
	}
	proxyTLS := s.proxyTLS.Clone()
	proxyTLS.RootCAs = tlsConfig.RootCAs
	// Requests/urllib3 applies the effective verification policy to both TLS
	// connections. Keep this exception scoped to the selected source's pool.
	proxyTLS.InsecureSkipVerify = tlsConfig.InsecureSkipVerify
	route := &proxy.OutboundRoute{ProxyURL: upstream, TLS: tlsConfig, ProxyTLS: proxyTLS}
	s.routes[key] = route
	return route, nil
}

func poetrySourceMatch(source, target string, modern bool) (int, bool) {
	if !modern {
		shared := 0
		for shared < len(source) && shared < len(target) && source[shared] == target[shared] {
			shared++
		}
		return shared, false
	}
	own := strings.FieldsFunc(source, func(r rune) bool { return r == '/' })
	other := strings.FieldsFunc(target, func(r rune) bool { return r == '/' })
	shared := 0
	for shared < len(own) && shared < len(other) && own[shared] == other[shared] {
		shared++
	}
	return shared, shared == len(own)
}

func (s *poetryProxySettings) upstreamProxy(target *url.URL) (*url.URL, error) {
	upstream, err := poetryProxyForURL(s.upstream)(target)
	if s.system.Bypasses(target) {
		upstream = nil
	}
	return upstream, err
}
