// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestPoetryDefaultTrustUsesSystemRootsWithoutRuntimeDiscovery(t *testing.T) {
	root := isolatedPoetryProject(t)
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	// Setup must work without inspecting or executing the Poetry launcher.
	manager := Poetry{executable: filepath.Join(root, "absent-launcher"), version: pm.Version{Major: 2, Minor: 5}, proxyState: &poetryProxyState{}}
	args := []string{"-C", root, "install"}
	options, err := manager.ProxyOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://public.example/project.whl")
	for _, agent := range []string{"poetry/2.5.1", "git-dulwich/0.24"} {
		route, err := options.RouteForRequest(proxy.Request{URL: *target, Header: http.Header{"User-Agent": {agent}}})
		if err != nil || !route.TLS.RootCAs.Equal(roots) || route.TLS.InsecureSkipVerify {
			t.Fatalf("%s did not use system trust: %v", agent, err)
		}
	}
	if _, err := manager.ProxyCommand(context.Background(), args, poetryInvocationConfig(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.executable); !os.IsNotExist(err) {
		t.Fatal("setup required or created a Poetry launcher")
	}
}

func TestPoetryExplicitTrustKeepsRequestsAndBundledGitSeparate(t *testing.T) {
	root := isolatedPoetryProject(t)
	requests, ssl := poetryInvocationConfig(t), poetryInvocationConfig(t)
	t.Setenv("REQUESTS_CA_BUNDLE", requests.CACertificatePath)
	t.Setenv("SSL_CERT_FILE", ssl.CACertificatePath)
	options, err := (Poetry{version: minPoetryVersion}).ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://public.example/project.whl")
	for _, test := range []struct{ agent, path string }{
		{"poetry/2.5.1", requests.CACertificatePath},
		{"git-dulwich/0.24", ssl.CACertificatePath},
	} {
		pem, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatal(err)
		}
		route, err := options.RouteForRequest(proxy.Request{URL: *target, Header: http.Header{"User-Agent": {test.agent}}})
		if err != nil || !route.TLS.RootCAs.Equal(configPool(t, pem)) {
			t.Fatalf("%s did not use its explicit CA bundle: %v", test.agent, err)
		}
	}
}

func TestPoetryGlobalAndProjectRepositoryContextsRemainDistinct(t *testing.T) {
	for _, localTrust := range []bool{false, true} {
		root := isolatedPoetryProject(t)
		poetrySettingsFixture(t, "repositories-overridden.toml", filepath.Join(root, "config.toml"))
		if localTrust {
			poetrySettingsFixture(t, "local-repository-trust.toml", filepath.Join(root, "poetry.toml"))
		}
		t.Setenv("https_proxy", "http://user:secret@gateway.example:8080")
		t.Setenv("no_proxy", "superseded.example")
		settings, err := readPoetrySettings([]string{"-C", root, "install"})
		if err != nil {
			t.Fatal(err)
		}
		if localTrust && (settings.global.get("certificates", "private", "verify") != false || settings.get("certificates", "private", "verify") != true) {
			t.Fatal("project settings mutated the global authenticator snapshot")
		}
		manager := Poetry{version: pm.Version{Major: 2, Minor: 5}, proxyState: &poetryProxyState{}}
		args := []string{"-C", root, "install"}
		options, err := manager.ProxyOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		config := poetryInvocationConfig(t)
		config.IdentityCertificate = func(identity string) (string, error) { return identity, nil }
		spec, err := manager.ProxyCommand(context.Background(), args, config)
		if err != nil {
			t.Fatal(err)
		}
		identity := spec.EnvOverrides["POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT"]
		for _, address := range []string{"https://superseded.example/project.whl", "https://index.example/simple/project/"} {
			target, _ := url.Parse(address)
			if _, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: identity}); err == nil || !strings.Contains(err.Error(), "proxy/TLS") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("conflicting authenticator contexts silently changed policy: %v", err)
			}
		}
	}
}

func TestPoetryRequestsAgentsCannotSelectBundledGitPolicy(t *testing.T) {
	root := isolatedPoetryProject(t)
	t.Setenv("GIT_HTTP_USER_AGENT", "poetry/2.5.1")
	ssl := poetryInvocationConfig(t)
	t.Setenv("SSL_CERT_FILE", ssl.CACertificatePath)
	requests := poetryInvocationConfig(t)
	t.Setenv("REQUESTS_CA_BUNDLE", requests.CACertificatePath)
	pem, err := os.ReadFile(requests.CACertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://public.example/project.whl")
	route, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: "poetry-default", Header: http.Header{"User-Agent": {"poetry/2.5.1"}}})
	if err != nil || !route.TLS.RootCAs.Equal(configPool(t, pem)) {
		t.Fatalf("native-only agent changed Requests trust: %v", err)
	}
}
