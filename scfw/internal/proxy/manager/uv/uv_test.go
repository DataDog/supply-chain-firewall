// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareUsesURLsAndFreezesSync(t *testing.T) {
	t.Setenv("UV_INDEX_URL", "https://legacy.example/simple")
	t.Setenv("UV_EXTRA_INDEX_URL", "https://legacy-extra.example/simple")
	prepared, err := (Manager{}).Prepare("uv", []string{"sync"}, "http://proxy/default/", map[string]string{"private": "http://proxy/private/"})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !strings.Contains(strings.Join(prepared.Args, " "), "--frozen") {
		t.Errorf("args = %v, want --frozen", prepared.Args)
	}
	environment := strings.Join(prepared.Env, "\n")
	if !strings.Contains(environment, "UV_DEFAULT_INDEX=http://proxy/default/") {
		t.Errorf("environment has invalid UV_DEFAULT_INDEX: %s", environment)
	}
	if !strings.Contains(environment, "UV_INDEX=private=http://proxy/private/") {
		t.Errorf("environment does not preserve named index: %s", environment)
	}
	if strings.Contains(environment, "UV_INDEX_URL=") || strings.Contains(environment, "UV_EXTRA_INDEX_URL=") {
		t.Errorf("environment retains superseded legacy indexes: %s", environment)
	}
}

func TestPrepareRecognizesSyncAfterGlobalOptions(t *testing.T) {
	prepared, err := (Manager{}).Prepare("uv", []string{"--offline", "sync"}, "http://proxy/default/", map[string]string{"private": "http://proxy/private/"})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !strings.Contains(strings.Join(prepared.Args, " "), "--frozen") {
		t.Errorf("args = %v, want --frozen", prepared.Args)
	}
	if environment := strings.Join(prepared.Env, "\n"); !strings.Contains(environment, "UV_INDEX=private=http://proxy/private/") {
		t.Errorf("environment does not preserve named project index: %s", environment)
	}
}

func TestRegistriesUsesLegacyEnvironmentPrecedence(t *testing.T) {
	config := filepath.Join(t.TempDir(), "uv.toml")
	if err := os.WriteFile(config, []byte("default-index = 'https://configured.example/simple'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UV_CONFIG_FILE", config)
	t.Setenv("UV_INDEX_URL", "https://legacy.example/simple")
	t.Setenv("UV_EXTRA_INDEX_URL", "https://extra.example/simple")
	t.Setenv("UV_DEFAULT_INDEX", "")
	t.Setenv("UV_INDEX", "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	configuration, err := (Manager{}).Registries(t.Context(), "uv", []string{"pip", "install", "demo"})
	if err != nil {
		t.Fatalf("Registries() error = %v", err)
	}
	if got := configuration.Default.String(); got != "https://legacy.example/simple/" {
		t.Errorf("default registry = %q", got)
	}
	if got := configuration.Named["index-a"].String(); got != "https://extra.example/simple/" {
		t.Errorf("extra registry = %q", got)
	}
}

func TestRegistriesRecognizesPipAfterGlobalOptions(t *testing.T) {
	config := filepath.Join(t.TempDir(), "uv.toml")
	contents := "default-index = 'https://project.example/simple'\n[pip]\nindex-url = 'https://pip.example/simple'\n"
	if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UV_CONFIG_FILE", config)
	t.Setenv("UV_INDEX_URL", "")
	t.Setenv("UV_DEFAULT_INDEX", "")
	t.Setenv("UV_INDEX", "")
	t.Setenv("UV_EXTRA_INDEX_URL", "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	configuration, err := (Manager{}).Registries(t.Context(), "uv", []string{"--offline", "pip", "install", "demo"})
	if err != nil {
		t.Fatalf("Registries() error = %v", err)
	}
	if got := configuration.Default.String(); got != "https://pip.example/simple/" {
		t.Errorf("default registry = %q, want pip registry", got)
	}
}

func TestRegistriesRejectsUnrepresentableIndexSecuritySettings(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{name: "explicit index", config: "[[index]]\nname = 'private'\nurl = 'https://private.example/simple'\nexplicit = true\n", wantErr: "explicit index"},
		{name: "insecure host", config: "allow-insecure-host = ['private.example']\n", wantErr: "allow-insecure-host"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "uv.toml")
			if err := os.WriteFile(config, []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("UV_CONFIG_FILE", config)
			t.Setenv("UV_INDEX", "")
			t.Setenv("UV_EXTRA_INDEX_URL", "")
			t.Setenv("UV_INSECURE_HOST", "")
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			_, err := (Manager{}).Registries(t.Context(), "uv", []string{"sync"})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Registries() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}
