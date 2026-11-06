// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"crypto/tls"
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
	"golang.org/x/net/http/httpproxy"
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

type poetryProxySettings struct {
	settings     poetrySettings
	upstream     httpproxy.Config
	system       pythonproxy.Settings
	registryTLS  *tls.Config
	registryErr  error
	proxyTLS     *tls.Config
	certificates []poetryCertificateRoute
	git          *poetryGitSettings
	modernPaths  bool
	mutex        sync.Mutex
	routes       map[string]*proxy.OutboundRoute
}

func (poetry Poetry) prepareProxy(command []string) (*poetryProxySettings, error) {
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
	// Poetry 1.x resolves --directory as its project location but keeps the
	// process working directory for network certificate paths and Git execution.
	if poetry.version != (pm.Version{}) && poetry.version.LessThan(pm.Version{Major: 2}) {
		settings.workingDirectory, err = os.Getwd()
		if err != nil {
			return nil, err
		}
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
	prepared.registryTLS, err = proxy.NewTLSConfig(proxy.TLSConfigOptions{CABundlePaths: []string{bundle}, ReplaceSystemRoots: bundle != ""})
	if err != nil {
		prepared.registryErr = err
		prepared.registryTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	prepared.proxyTLS = prepared.registryTLS.Clone()
	sources := slices.Clone(settings.sources)
	hasPrimary, hasPyPI := false, false
	for _, source := range sources {
		hasPrimary = hasPrimary || source.Priority == "primary"
		hasPyPI = hasPyPI || source.Name == "pypi"
	}
	if !hasPrimary && !hasPyPI {
		sources = append(sources, poetrySource{Name: "pypi", URL: "https://pypi.org/simple/"})
	}
	for _, source := range sources {
		if source.URL == "" && source.Name == "pypi" {
			source.URL = "https://pypi.org/simple/"
		}
		address, err := url.Parse(source.URL)
		if err != nil || address.Host == "" {
			return nil, errors.New("invalid Poetry source URL")
		}
		cert := settings.get("certificates", source.Name, "cert")
		verify := settings.get("certificates", source.Name, "verify")
		if verify == nil {
			verify = cert
		}
		path := settings.certificatePath(cert)
		if _, boolean := cert.(bool); boolean {
			path = ""
		}
		enabled := poetryBoolean(verify, true)
		// A string certificate path is a verify path, not a boolean switch.
		if text, isString := verify.(string); isString {
			enabled = true
			path = settings.certificatePath(text)
		}

		if path == "" && enabled {
			path = bundle
		}
		clientCertificate := settings.certificatePath(settings.get("certificates", source.Name, "client-cert"))
		tlsConfig, err := proxy.NewTLSConfig(proxy.TLSConfigOptions{CABundlePaths: []string{path}, ReplaceSystemRoots: path != "", ClientCertificatePath: clientCertificate})
		if err != nil {
			prepared.certificates = append(prepared.certificates, poetryCertificateRoute{source: source, address: address, err: err})
			continue
		}
		tlsConfig.InsecureSkipVerify = !enabled // Explicit, source-scoped Poetry verification setting.
		prepared.certificates = append(prepared.certificates, poetryCertificateRoute{source: source, address: address, tls: tlsConfig})
	}
	prepared.git, err = readPoetryGitSettings(settings)
	if err != nil {
		return nil, err
	}
	if len(settings.gitURLs) > 0 && prepared.git.executable == "" {
		return nil, errors.New("git is required to discover routing and TLS settings for Poetry Git dependencies")
	}
	if !prepared.git.native && poetry.version.LessThan(pm.Version{Major: 2}) {
		for _, address := range settings.gitURLs {
			target, err := url.Parse(address)
			if err != nil {
				continue
			}
			values, err := prepared.git.values(target)
			if err != nil {
				return nil, err
			}
			verification, present := values["sslverify"]
			if target.Scheme == "https" && values["sslcainfo"] != "" && (!present || poetryBoolean(verification, true)) {
				return nil, errors.New("the bundled Poetry Git client cannot apply the configured Git CA through process-only overrides; enable experimental.system-git-client with POETRY_EXPERIMENTAL_SYSTEM_GIT_CLIENT=true for this invocation")
			}
		}
	}
	if poetry.proxyState != nil {
		poetry.proxyState.command = slices.Clone(command)
		poetry.proxyState.prepared = prepared
	}
	return prepared, nil
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

func (s *poetryProxySettings) route(request proxy.Request) (*proxy.OutboundRoute, error) {
	if s.git.isRequest(request) {
		return s.git.route(request)
	}
	source := -1
	best, contained := -1, false
	for i, configured := range s.certificates {
		if !strings.EqualFold(request.URL.Host, configured.address.Host) || (configured.address.Scheme == "https" && request.URL.Scheme != "https") {
			continue
		}
		score, inside := poetrySourceMatch(configured.address.Path, request.URL.Path, s.modernPaths)
		if source < 0 || score > best || (score == best && inside && !contained) {
			source, best, contained = i, score, inside
		}
	}
	tlsConfig := s.registryTLS
	if source >= 0 {
		if s.certificates[source].err != nil {
			return nil, s.certificates[source].err
		}
		tlsConfig = s.certificates[source].tls
	} else if s.registryErr != nil {
		return nil, s.registryErr
	}
	upstream, err := poetryProxyForURL(s.upstream)(&request.URL)
	if err != nil {
		return nil, err
	}
	if s.system.Bypasses(&request.URL) {
		upstream = nil
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
