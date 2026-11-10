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
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/gitproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

const poetryNativeGitClient = "native-git"

func (s *poetryGitSettings) isRequest(request proxy.Request) bool {
	agent := request.Header.Get("User-Agent")
	if strings.HasPrefix(request.ClientIdentity, "poetry-source-") || poetryRequestsAgent(agent) {
		return false
	}
	// File-configured user agents do not select a process client policy.
	return strings.HasPrefix(agent, "git/") || strings.HasPrefix(agent, "git-dulwich/") || request.URL.Query().Get("service") == "git-upload-pack" || strings.HasSuffix(request.URL.Path, "/git-upload-pack")
}

func poetryRequestsAgent(agent string) bool {
	return strings.HasPrefix(agent, "poetry/") || strings.HasPrefix(agent, "python-requests/")
}

func (s *poetryGitSettings) childOverrides(overrides map[string]string, config proxy.ClientConfig) error {
	native, ok := config.AdditionalClients[poetryNativeGitClient]
	if !ok {
		return errors.New("native Git proxy configuration is missing")
	}
	// Trust both invocation listeners in the shared child Git CA setting.
	// Native outbound trust comes from its Git snapshot; process Git uses
	// system roots and explicit SSL CA paths.
	bundle, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		return errors.New("could not read invocation proxy CA")
	}
	nativeCA, err := os.ReadFile(native.CACertificatePath)
	if err != nil {
		return errors.New("could not read invocation Git CA")
	}
	bundle = append(append(bundle, '\n'), nativeCA...)
	native.CACertificatePath = filepath.Join(filepath.Dir(config.CACertificatePath), "git-ca.pem")
	if err := os.WriteFile(native.CACertificatePath, bundle, 0600); err != nil {
		return errors.New("could not prepare invocation Git CA bundle")
	}
	native.AdditionalClients = config.AdditionalClients
	return s.snapshot.ChildOverrides(overrides, native)
}

type poetryGitSettings struct {
	snapshot *gitproxy.Settings
	tls      *tls.Config
	tlsErr   error
	mutex    sync.Mutex
	routes   map[string]*proxy.OutboundRoute
}

func readPoetryGitSettings(settings poetrySettings) (*poetryGitSettings, error) {
	snapshot, err := gitproxy.Read(settings.workingDirectory)
	if err != nil {
		return nil, err
	}
	var paths []string
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		paths = append(paths, settings.workingPath(path))
	}
	for _, path := range filepath.SplitList(os.Getenv("SSL_CERT_DIR")) {
		if path != "" {
			paths = append(paths, settings.workingPath(path))
		}
	}
	options := proxy.TLSConfigOptions{CABundlePaths: paths}
	if len(paths) > 0 {
		options.RootCAs = x509.NewCertPool()
	}
	tlsConfig, tlsErr := proxy.NewTLSConfig(options)
	return &poetryGitSettings{snapshot: snapshot, tls: tlsConfig, tlsErr: tlsErr, routes: map[string]*proxy.OutboundRoute{}}, nil
}

// processRoute uses captured proxies, explicit SSL CA paths, and Go system roots.
// Git-file precedence and client-specific URL matching are not emulated.
func (s *poetryGitSettings) processRoute(scheme string, upstream *url.URL) (*proxy.OutboundRoute, error) {
	key := scheme
	if upstream != nil {
		key += "/" + upstream.String()
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if route := s.routes[key]; route != nil {
		return route, nil
	}
	route := &proxy.OutboundRoute{ProxyURL: upstream}
	if scheme == "https" || (upstream != nil && upstream.Scheme == "https") {
		if s.tlsErr != nil {
			return nil, s.tlsErr
		}
		if scheme == "https" {
			route.TLS = s.tls
		}
		if upstream != nil && upstream.Scheme == "https" {
			route.ProxyTLS = s.tls.Clone()
		}
	}
	s.routes[key] = route
	return route, nil
}
