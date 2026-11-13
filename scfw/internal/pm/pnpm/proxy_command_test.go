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
		kept    []string
	}{
		{10, "add x --https-pro=http://evil:1 --config.noproxy=registry.npmjs.org", []string{"add", "x"}},
		{11, "add x --https-pro=http://evil:1 --config.noproxy=registry.npmjs.org", []string{"add", "x"}},
		{12, "add x --https-proxy http://evil:1 --no-proxy=reg", []string{"add", "x"}},
		// pnpm 12 applies configuration options anywhere after create and pipeline.
		{12, "create vite --config.https-proxy=http://evil:1 --config.noproxy=registry.npmjs.org --template react", []string{"create", "vite", "--template", "react"}},
		{12, "pipeline --config.https-proxy=http://evil:1 --no-proxy=reg", []string{"pipeline"}},
	} {
		newPnpmWorkspace(t)
		config, pem := testClientConfig(t)
		manager := fakePnpm(t, pnpmVersions[test.major])
		spec, err := manager.ProxyCommand(context.Background(), strings.Fields(test.command), config)
		if err != nil {
			t.Fatal(err)
		}
		if want := append(proxyOverrides(config, pem), test.kept...); !slices.Equal(spec.Args, want) {
			t.Errorf("pnpm %d: args = %q, want %q", test.major, spec.Args, want)
		}
		if upstream, err := manager.UpstreamProxy(strings.Fields(test.command)); err != nil || upstream.HTTPSProxy != "http://evil:1" {
			t.Errorf("pnpm %d: stripped options must still select the upstream, got %q (error %v)", test.major, upstream.HTTPSProxy, err)
		}
	}
}

// `pnpm with <version>` runs that release as a child with only the arguments
// after the version, so the overrides must reach the child too.
func TestProxyCommandWithNestsOverrides(t *testing.T) {
	for _, installed := range []string{"11.28.9", "12.18.0"} {
		newPnpmWorkspace(t)
		config, pem := testClientConfig(t)
		manager := fakePnpm(t, installed)
		spec, err := manager.ProxyCommand(context.Background(), strings.Fields("with 10.34.9 add x --config.noproxy=registry.npmjs.org"), config)
		if err != nil {
			t.Fatal(err)
		}
		want := slices.Concat(proxyOverrides(config, pem), []string{"with", "10.34.9"}, proxyOverrides(config, pem), []string{"add", "x"})
		if !slices.Equal(spec.Args, want) {
			t.Errorf("pnpm %s: args = %q, want %q", installed, spec.Args, want)
		}
		if _, err := manager.ProxyCommand(context.Background(), strings.Fields("with latest add x"), config); err == nil || !strings.Contains(err.Error(), "with") {
			t.Errorf("pnpm %s: with latest error = %v, want a refusal", installed, err)
		}
		spec, err = manager.ProxyCommand(context.Background(), strings.Fields("with current add x"), config)
		if want := append(proxyOverrides(config, pem), "with", "current", "add", "x"); err != nil || !slices.Equal(spec.Args, want) {
			t.Errorf("pnpm %s: with current args = %q (error %v), want %q", installed, spec.Args, err, want)
		}
	}
}

// Each nested `with` starts another pnpm that sees only what follows its
// version, so every level needs the overrides.
func TestProxyCommandNestedWith(t *testing.T) {
	newPnpmWorkspace(t)
	config, pem := testClientConfig(t)
	manager := fakePnpm(t, "11.28.9")
	overrides := proxyOverrides(config, pem)
	for command, want := range map[string][]string{
		"with 11.28.9 with 12.18.0 add x --config.no-proxy=registry.npmjs.org": slices.Concat(
			overrides, []string{"with", "11.28.9"}, overrides, []string{"with", "12.18.0"}, overrides, []string{"add", "x"}),
		"with 12 with 11.28.9 with 12 add x --config.noproxy=registry.npmjs.org": slices.Concat(
			overrides, []string{"with", "12"}, overrides, []string{"with", "11.28.9"}, overrides, []string{"with", "12"}, overrides, []string{"add", "x"}),
	} {
		spec, err := manager.ProxyCommand(context.Background(), strings.Fields(command), config)
		if err != nil || !slices.Equal(spec.Args, want) {
			t.Errorf("%q: args = %q (error %v), want %q", command, spec.Args, err, want)
		}
	}
	if _, err := manager.ProxyCommand(context.Background(), strings.Fields("with 12.18.0 with latest add x"), config); err == nil || !strings.Contains(err.Error(), "with") {
		t.Errorf("a nested non-exact version must be refused, error = %v", err)
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
