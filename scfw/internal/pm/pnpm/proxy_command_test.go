// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func testClientConfig(t *testing.T) (proxy.ClientConfig, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	writePnpmFixture(t, path, "tls/scfw-ca.pem")
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: path}, string(pem)
}

func proxyOverrides(config proxy.ClientConfig, pem string) []string {
	return []string{
		"--config.https-proxy=" + config.URL, "--config.proxy=" + config.URL, "--config.http-proxy=" + config.URL,
		"--config.noproxy=scfw.invalid", "--config.no-proxy=scfw.invalid",
		"--config.cafile=" + config.CACertificatePath, "--config.ca=" + pem,
	}
}

func TestProxyCommandArgs(t *testing.T) {
	for major, version := range pnpmVersions {
		layout := newPnpmWorkspace(t)
		config, pem := testClientConfig(t)
		manager := fakePnpm(t, version)
		for command, tail := range map[string][]string{
			"add x":                     {"add", "x"},
			"-C sub add x -- --proxy p": {"-C", "sub", "add", "x", "--", "--proxy", "p"},
		} {
			spec, err := manager.ProxyCommand(context.Background(), strings.Fields(command), config)
			if err != nil {
				t.Fatal(err)
			}
			if want := append(proxyOverrides(config, pem), tail...); spec.Executable != manager.Executable() || !slices.Equal(spec.Args, want) {
				t.Errorf("pnpm %d %q: command = %s %q, want %q", major, command, spec.Executable, spec.Args, want)
			}
		}
		writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/registry-cafile.npmrc.tmpl", filepath.Join(testdataDir, "tls", "registry-ca.pem"))
		spec, err := manager.ProxyCommand(context.Background(), []string{"add", "x"}, config)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(spec.Args, "--config.//registry.test/:cafile="+config.CACertificatePath) {
			t.Errorf("pnpm %d: per-registry CA override missing from %q", major, spec.Args)
		}
	}
}

func TestProxyCommandStripsUserNetworkFlags(t *testing.T) {
	for _, test := range []struct {
		major   int
		command string
	}{
		{10, "add x --https-pro=http://evil:1 --config.noproxy=registry.npmjs.org"},
		{11, "add x --https-pro=http://evil:1 --config.noproxy=registry.npmjs.org"},
		{12, "add x --https-proxy http://evil:1 --no-proxy=reg"},
	} {
		newPnpmWorkspace(t)
		config, pem := testClientConfig(t)
		manager := fakePnpm(t, pnpmVersions[test.major])
		spec, err := manager.ProxyCommand(context.Background(), strings.Fields(test.command), config)
		if err != nil {
			t.Fatal(err)
		}
		if want := append(proxyOverrides(config, pem), "add", "x"); !slices.Equal(spec.Args, want) {
			t.Errorf("pnpm %d: args = %q, want %q", test.major, spec.Args, want)
		}
		if upstream, err := manager.UpstreamProxy(strings.Fields(test.command)); err != nil || upstream.HTTPSProxy != "http://evil:1" {
			t.Errorf("pnpm %d: stripped options must still select the upstream, got %q (error %v)", test.major, upstream.HTTPSProxy, err)
		}
	}
}

func TestProxyCommandDlxPlacement(t *testing.T) {
	for major, version := range pnpmVersions {
		newPnpmWorkspace(t)
		config, pem := testClientConfig(t)
		spec, err := fakePnpmNamed(t, "pnpx", version).ProxyCommand(context.Background(), []string{"cowsay", "--help"}, config)
		if want := append(proxyOverrides(config, pem), "cowsay", "--help"); err != nil || !slices.Equal(spec.Args, want) {
			t.Errorf("pnpm %d: pnpx args = %q (error %v), want %q", major, spec.Args, err, want)
		}
		spec, err = fakePnpm(t, version).ProxyCommand(context.Background(), []string{"dlx", "cowsay", "--version"}, config)
		if want := append(proxyOverrides(config, pem), "dlx", "cowsay", "--version"); err != nil || !slices.Equal(spec.Args, want) {
			t.Errorf("pnpm %d: dlx args = %q (error %v), want %q", major, spec.Args, err, want)
		}
	}
}

func TestProxyCommandEnvironment(t *testing.T) {
	newPnpmWorkspace(t)
	config, pem := testClientConfig(t)
	t.Setenv("No_Proxy", "reg")
	t.Setenv("NPM_CONFIG_NOPROXY", "reg")
	t.Setenv("PNPM_CONFIG_HTTPS_PROXY", "http://old:1")
	t.Setenv("pnpm_config_registry", "https://r.test/")
	spec, err := fakePnpm(t, "11.28.9").ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	ca := config.CACertificatePath
	for key, value := range map[string]string{
		"HTTPS_PROXY": config.URL, "https_proxy": config.URL, "HTTP_PROXY": config.URL, "ALL_PROXY": config.URL,
		"NO_PROXY": "", "no_proxy": "",
		"npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL, "npm_config_cafile": ca,
		"npm_config_noproxy": "scfw.invalid", "npm_config_no_proxy": "scfw.invalid",
		"pnpm_config_proxy": config.URL, "pnpm_config_http_proxy": config.URL, "pnpm_config_https_proxy": config.URL,
		"pnpm_config_noproxy": "scfw.invalid", "pnpm_config_no_proxy": "scfw.invalid",
		"pnpm_config_cafile": ca, "pnpm_config_ca": pem,
		"NODE_EXTRA_CA_CERTS": ca, "GIT_SSL_CAINFO": ca,
		"No_Proxy": "", "NPM_CONFIG_NOPROXY": "scfw.invalid", "PNPM_CONFIG_HTTPS_PROXY": config.URL,
	} {
		if actual, found := spec.EnvOverrides[key]; !found || actual != value {
			t.Errorf("%s = %q (present %v), want %q", key, actual, found, value)
		}
	}
	if _, found := spec.EnvOverrides["pnpm_config_registry"]; found {
		t.Error("unrelated pnpm configuration must not be overridden")
	}
}

func TestProxyCommandRejectsUnreadableCA(t *testing.T) {
	newPnpmWorkspace(t)
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: filepath.Join(t.TempDir(), "missing-secret.pem")}
	_, err := fakePnpm(t, "11.28.9").ProxyCommand(context.Background(), []string{"install"}, config)
	if err == nil || err.Error() != "read proxy CA certificate" {
		t.Fatalf("error = %v", err)
	}
}
