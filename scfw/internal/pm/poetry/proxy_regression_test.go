// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"crypto/x509"
	"fmt"

	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func configPool(t *testing.T, ca []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	return pool
}

func poetryInvocationConfig(t *testing.T, clients ...map[string]proxy.Options) proxy.ClientConfig {
	t.Helper()
	start := func(options proxy.Options) proxy.ClientConfig {
		server, err := proxy.Start(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		return server.ClientConfig()
	}
	config := start(proxy.Options{})
	additional := map[string]proxy.Options{"native-git": {}}
	if len(clients) > 0 {
		additional = clients[0]
	}
	config.AdditionalClients = map[string]proxy.ClientConfig{}
	for name, options := range additional {
		config.AdditionalClients[name] = start(options)
	}
	return config
}

func isolatedPoetryProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, ".config"))
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("POETRY_CONFIG_DIR", root)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "absent-gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	for _, name := range []string{"GIT_CONFIG_PARAMETERS", "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "no_proxy", "NO_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_CERT", "GIT_SSL_KEY", "SSL_CERT_FILE", "SSL_CERT_DIR", "POETRY_SYSTEM_GIT_CLIENT", "POETRY_CERTIFICATES_PRIVATE_CERT", "POETRY_CERTIFICATES_PRIVATE_VERIFY", "POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	poetrySettingsFixture(t, "proxy-project.toml", filepath.Join(root, "pyproject.toml"))
	return root
}

func TestPoetryRelativeRequestsTrust(t *testing.T) {
	root := isolatedPoetryProject(t)
	config := poetryInvocationConfig(t)
	ca, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	// Environment paths remain literal even when they look like Poetry placeholders.
	filename := "literal-{cache-dir}.pem"
	if err := os.WriteFile(filepath.Join(root, filename), ca, 0600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	poetrySettingsFixture(t, "proxy-project.toml", filepath.Join(project, "pyproject.toml"))
	t.Chdir(t.TempDir())
	for _, version := range []pm.Version{{Major: 2}, {Major: 2, Minor: 5}} {
		for _, key := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
			for _, path := range []string{filename, ".", filepath.Join(root, filename)} {
				t.Run(version.String()+"/"+key+"/"+path, func(t *testing.T) {
					t.Setenv(key, path)
					if key == "REQUESTS_CA_BUNDLE" {
						t.Setenv("CURL_CA_BUNDLE", "/ignored/missing.pem")
					}
					manager := Poetry{version: version}
					options, err := manager.ProxyOptions([]string{"--directory", root, "--project", "project", "install"})
					if err != nil {
						t.Fatal(err)
					}
					target, _ := url.Parse("https://index.example/simple/project/")
					route, err := options.RouteForRequest(proxy.Request{URL: *target})
					if err != nil || route.TLS.RootCAs == nil {
						t.Fatalf("relative trust not loaded: %v", err)
					}
					if !route.TLS.RootCAs.Equal(configPool(t, ca)) {
						t.Fatal("environment CA did not replace default roots")
					}
				})
			}
		}
	}
}

func TestPoetryVerificationOverridesCertificatePath(t *testing.T) {
	root := isolatedPoetryProject(t)
	config := poetryInvocationConfig(t)
	template, err := os.ReadFile("testdata/verification-settings.toml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, verify, bundle, client string
		insecure, fail               bool
	}{
		{name: "true uses environment trust", verify: "true", bundle: config.CACertificatePath},
		{name: "false ignores stale trust", verify: "false", bundle: "/ignored/missing.pem", insecure: true},
		{name: "path overrides old cert", verify: strconv.Quote(config.CACertificatePath), bundle: "/ignored/missing.pem"},
		{name: "client certificate remains independent", verify: "false", client: "/missing/client.pem", insecure: true, fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("REQUESTS_CA_BUNDLE", test.bundle)
			data := fmt.Sprintf(string(template), strconv.Quote("/shadowed/missing.pem"), test.verify, strconv.Quote(test.client))
			path := filepath.Join(root, "poetry.toml")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
			options, err := manager.ProxyOptions([]string{"--directory", root, "install"})
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse("https://index.example/simple/project/")
			route, err := options.RouteForRequest(proxy.Request{URL: *target})
			if test.fail {
				if err == nil || strings.Contains(err.Error(), "client.pem") {
					t.Fatalf("missing/unsafe client certificate error: %v", err)
				}
				return
			}
			if err != nil || route.TLS.InsecureSkipVerify != test.insecure {
				t.Fatalf("effective verification was not honored: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatal("source TLS configuration changed")
			}
		})
	}
}
