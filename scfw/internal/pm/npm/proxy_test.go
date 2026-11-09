// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func testClientConfig(t *testing.T) (proxy.ClientConfig, string) {
	t.Helper()
	pem := readNpmFixture(t, "tls/scfw-ca.pem")
	path := filepath.Join(t.TempDir(), "ca.pem")
	writeNpmFixture(t, path, pem)
	return proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: path}, pem
}

func scfwFlags(config proxy.ClientConfig, pem string) []string {
	return []string{
		"--https-proxy=" + config.URL, "--proxy=" + config.URL, "--noproxy=scfw.invalid",
		"--cafile=" + config.CACertificatePath, "--ca=" + pem,
	}
}

func TestProxyCommandInsertsFlagsBeforeSeparator(t *testing.T) {
	config, pem := testClientConfig(t)
	command := []string{"exec", "--yes", "--package=x", "--", "node", "-e", "1"}
	original := slices.Clone(command)
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Concat([]string{"exec", "--yes", "--package=x"}, scfwFlags(config, pem), []string{"--", "node", "-e", "1"})
	if !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
	if !slices.Equal(command, original) {
		t.Fatalf("caller's command was mutated: %q", command)
	}
}

func TestProxyCommandAppendsFlagsWithoutSeparator(t *testing.T) {
	config, pem := testClientConfig(t)
	command := []string{"--prefix", "/p", "install", "left-pad"}
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Executable != "/bin/npm" {
		t.Fatalf("executable = %q", spec.Executable)
	}
	if want := slices.Concat(command, scfwFlags(config, pem)); !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
}

func TestProxyCommandRejectsUnreadableCACertificate(t *testing.T) {
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: filepath.Join(t.TempDir(), "missing-secret.pem")}
	_, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install"}, config)
	if err == nil || err.Error() != "read proxy CA certificate" {
		t.Fatalf("error = %v", err)
	}
}

func TestProxyCommandBundlesUserNodeExtraCACerts(t *testing.T) {
	config, pem := testClientConfig(t)
	userCA := "-----BEGIN CERTIFICATE-----\nuser\n-----END CERTIFICATE-----\n"
	userFile := filepath.Join(t.TempDir(), "corporate.pem")
	writeNpmFixture(t, userFile, userCA)
	t.Setenv("NODE_EXTRA_CA_CERTS", userFile)
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	bundle := spec.EnvOverrides["NODE_EXTRA_CA_CERTS"]
	if filepath.Dir(bundle) != filepath.Dir(config.CACertificatePath) || bundle == config.CACertificatePath {
		t.Fatalf("bundle %q must be a separate file in the per-run CA directory", bundle)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != userCA+"\n"+pem {
		t.Fatalf("bundle = %q", data)
	}
	if spec.EnvOverrides["npm_config_cafile"] != config.CACertificatePath || spec.EnvOverrides["GIT_SSL_CAINFO"] != config.CACertificatePath {
		t.Fatal("only NODE_EXTRA_CA_CERTS may point at the bundle")
	}
}

func TestProxyCommandIgnoresUnreadableNodeExtraCACerts(t *testing.T) {
	config, _ := testClientConfig(t)
	t.Setenv("NODE_EXTRA_CA_CERTS", filepath.Join(t.TempDir(), "missing.pem"))
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvOverrides["NODE_EXTRA_CA_CERTS"] != config.CACertificatePath {
		t.Fatalf("NODE_EXTRA_CA_CERTS = %q", spec.EnvOverrides["NODE_EXTRA_CA_CERTS"])
	}
}

func TestProxyEnvironmentOverrides(t *testing.T) {
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: "/run/ca.pem"}
	got := proxyEnvironmentOverrides(nil, config, "PEM")
	want := map[string]string{
		"HTTP_PROXY": config.URL, "http_proxy": config.URL, "HTTPS_PROXY": config.URL, "https_proxy": config.URL,
		"ALL_PROXY": config.URL, "all_proxy": config.URL, "npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL,
		"NO_PROXY": "", "no_proxy": "", "npm_config_noproxy": "scfw.invalid",
		"npm_config_cafile": "/run/ca.pem", "NODE_EXTRA_CA_CERTS": "/run/ca.pem", "GIT_SSL_CAINFO": "/run/ca.pem",
		"npm_config_ca": "PEM",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("overrides = %v, want %v", got, want)
	}
}

func TestProxyEnvironmentOverridesCoverExistingVariants(t *testing.T) {
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: "/run/ca.pem"}
	environ := []string{
		"NPM_CONFIG_HTTPS_PROXY=http://corp", "npm_config_https-proxy=http://corp", "Npm_Config_Noproxy=x",
		"No_Proxy=x", "NPM_CONFIG_CA=pem", "Https_Proxy=http://corp", "NPM_CONFIG_REGISTRY=https://r",
	}
	got := proxyEnvironmentOverrides(environ, config, "PEM")
	for key, value := range map[string]string{
		"NPM_CONFIG_HTTPS_PROXY": config.URL, "npm_config_https-proxy": config.URL, "Npm_Config_Noproxy": "scfw.invalid",
		"No_Proxy": "", "NPM_CONFIG_CA": "PEM", "Https_Proxy": config.URL,
	} {
		if actual, found := got[key]; !found || actual != value {
			t.Errorf("%s = %q (present %v), want %q", key, actual, found, value)
		}
	}
	if _, found := got["NPM_CONFIG_REGISTRY"]; found {
		t.Error("unrelated npm configuration must not be overridden")
	}
}
