// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func copyFixture(t *testing.T, name, target string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// isolateBun clears the environment Bun settings come from.
func isolateBun(t *testing.T) string {
	t.Helper()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
		"BUN_CONFIG_REGISTRY", "NPM_CONFIG_REGISTRY", "npm_config_registry", "NPM_CONFIG_USERCONFIG", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"} {
		t.Setenv(key, "")
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	return root
}

func TestSettingsReadsEnvironmentNpmrcAndBunfig(t *testing.T) {
	root := isolateBun(t)
	project := filepath.Join(root, "project")
	copyFixture(t, "npmrc", filepath.Join(project, ".npmrc"))
	copyFixture(t, "bunfig.toml", filepath.Join(project, "sub", "custom.toml"))
	copyFixture(t, "global.bunfig.toml", filepath.Join(root, "config", ".bunfig.toml"))
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	t.Setenv("HTTPS_PROXY", "http://user:secret@proxy.example:8080")
	t.Setenv("no_proxy", "internal.example")
	t.Setenv("NPM_CONFIG_REGISTRY", "https://env.example/")
	t.Setenv("SCOPE_HOST", "table-scope.example")

	settings, _, err := (Bun{installed: version14}).settings([]string{"--cwd=sub", "--config=custom.toml", "add", "--registry=https://cli.example/", "--cafile=cli.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if settings.HTTPS != "http://user:secret@proxy.example:8080" || settings.NoProxy != "internal.example" {
		t.Fatalf("routing = %+v", settings)
	}
	for _, registry := range []string{"https://env.example/", "https://cli.example/", "https://npmrc.example/", "https://scoped.example/",
		"https://global.example/", "https://bunfig.example/", "https://string-scope.example/", "https://table-scope.example/"} {
		if !slices.Contains(settings.Registries, registry) {
			t.Errorf("registries %q miss %s", settings.Registries, registry)
		}
	}
	for _, file := range []string{filepath.Join(project, "sub", "cli.pem"), filepath.Join(project, "npmrc-ca.pem"), filepath.Join(project, "sub", "bunfig-ca.pem")} {
		if !slices.Contains(settings.CAFiles, file) {
			t.Errorf("CA files %q miss %s", settings.CAFiles, file)
		}
	}
	if !slices.Contains(settings.CA, "-----BEGIN CERTIFICATE-----inline") {
		t.Errorf("CA = %q", settings.CA)
	}
}

func TestSettingsSkipsMalformedBunfig(t *testing.T) {
	root := isolateBun(t)
	copyFixture(t, "malformed.bunfig.toml", filepath.Join(root, "bunfig.toml"))
	t.Chdir(root)
	settings, _, err := (Bun{installed: version14}).settings([]string{"install"})
	if err != nil || len(settings.CAFiles) != 0 {
		t.Fatalf("settings = %+v, %v", settings, err)
	}
}
