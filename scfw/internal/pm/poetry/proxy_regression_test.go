// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

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
