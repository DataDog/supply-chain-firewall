// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestInlineScriptSettings(t *testing.T) {
	fixtures, _ := filepath.Abs("testdata")
	isolatedEnvironment(t)
	root, _ := os.Getwd()
	path := filepath.Join(root, "scripts", "entrypoint.py")
	original := copyFixture(t, filepath.Join(fixtures, "scripts"), "settings.py", path)
	config := filepath.Join(root, "uv.toml")
	copyConfigurationFixture(t, fixtures, "project", config)
	manager := UV{}
	for _, args := range [][]string{
		{"run", path}, {"run", "--", path, "--help", "--config-file=child.toml"},
		{"--no-config", "run", path}, {"--config-file", config, "run", path},
		{"run", "--script", path}, {"run", "-s", path}, {"run", "-vs", path}, {"run", "--gui-script", path},
		{"run", "--directory", filepath.Dir(path), "entrypoint.py"},
		{"add", "--script", path, "project"}, {"lock", "--script=" + path},
		{"remove", "--script", path, "project"}, {"export", "--script", path}, {"tree", "--script", path},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			settings, err := manager.settings(args)
			if err != nil {
				t.Fatal(err)
			}
			if settings["resolution"] != "lowest" || settings["sources"] != nil {
				t.Fatalf("inline settings: %v", settings)
			}
			links, _ := settings["find-links"].([]any)
			if len(links) == 0 || links[0] != filepath.Join(filepath.Dir(path), "wheels") {
				t.Fatalf("inline relative path lost its origin: %v", links)
			}
			options, err := manager.PyPIClassifierOptions(args)
			if err != nil || !slices.Contains(options.SimpleIndexURLs, "https://script.example/custom/") {
				t.Fatalf("inline index discovery: %+v/%v", options, err)
			}
			project, err := manager.ProjectDirectory(args)
			if args[0] == "run" && (err != nil || project != filepath.Dir(path)) {
				t.Fatalf("script discovery root: %s/%v", project, err)
			}
		})
	}
	settings, err := manager.settings([]string{"--no-config", "run", path})
	if err != nil || !reflect.DeepEqual(settings["allow-insecure-host"], []any{"script.example"}) {
		t.Fatalf("inline trust was lost with no-config: %v/%v", settings, err)
	}
	configurer := UV{executable: "uv"}
	configCA := proxy.ClientConfig{URL: "http://127.0.0.1:1234", CACertificatePath: filepath.Join(t.TempDir(), "ca.pem")}
	spec, err := configurer.ProxyCommand(context.Background(), []string{"run", path}, configCA)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := readSettings(spec.EnvOverrides["UV_CONFIG_FILE"], false)
	if err != nil || invocation["resolution"] != nil || invocation["index"] != nil {
		t.Fatalf("inline settings copied into invocation config: %v/%v", invocation, err)
	}
	if !reflect.DeepEqual(invocation["find-links"], []any{filepath.Join(root, "project-wheels")}) {
		t.Fatalf("inline arrays would be merged twice: %v", invocation["find-links"])
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, original) {
		t.Fatal("script was modified")
	}
	if err := os.WriteFile(path, bytes.ReplaceAll(original, []byte("\n"), []byte("\r\n")), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err = manager.settings([]string{"--no-config", "run", path})
	if err != nil || settings["resolution"] != "lowest" {
		t.Fatalf("CRLF script metadata: %v/%v", settings, err)
	}
}

func TestScriptInspectionRejectsUnsafeSettings(t *testing.T) {
	fixtures, _ := filepath.Abs("testdata/scripts")
	isolatedEnvironment(t)
	config := filepath.Join(t.TempDir(), "uv.toml")
	copyConfigurationFixture(t, filepath.Dir(fixtures), "project", config)
	for _, test := range []struct {
		name, fixture, proxy string
	}{
		{"http-proxy", "proxy.py.tmpl", "http-proxy"},
		{"https-proxy", "proxy.py.tmpl", "https-proxy"},
		{"invalid", "invalid.py", ""},
		{"unclosed", "unclosed.py", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "script.py")
			var values []any
			if test.proxy != "" {
				values = []any{test.proxy}
			}
			original := copyFixture(t, fixtures, test.fixture, path, values...)
			for _, args := range [][]string{
				{"run", path}, {"--no-config", "run", path}, {"lock", "--script", path},
				{"--config-file", config, "run", path},
			} {
				_, err := (UV{}).ProxyOptions(args)
				if err == nil || strings.Contains(err.Error(), "credential-secret") {
					t.Fatalf("%v: missing or unsafe error: %v", args, err)
				}
			}
			content, _ := os.ReadFile(path)
			if !bytes.Equal(content, original) {
				t.Fatal("rejected script was modified")
			}
		})
	}
	for _, args := range [][]string{
		{"run", "-"}, {"run", "--", "-"}, {"run", "https://user:credential-secret@example.com/script.py"},
		{"run", "http://example.com/script.py"}, {"run", "--script", "missing"},
	} {
		_, err := (UV{}).ProxyOptions(args)
		if err == nil || strings.Contains(err.Error(), "credential-secret") {
			t.Fatalf("%v: missing or unsafe error: %v", args, err)
		}
	}
}

func TestScriptInspectionBoundsAndOrdinaryCommands(t *testing.T) {
	fixtures, _ := filepath.Abs("testdata/scripts")
	isolatedEnvironment(t)
	path := filepath.Join(t.TempDir(), "entrypoint")
	copyFixture(t, fixtures, "ordinary.py", path)
	settings, err := (UV{}).settings([]string{"run", "--script", path})
	if err != nil || len(settings) != 0 {
		t.Fatalf("ordinary script: %v/%v", settings, err)
	}
	copyFixture(t, fixtures, "settings.py", path)
	for _, flags := range [][]string{{"--script"}, {"-s"}, {"-vs"}, {"-vp", "3.12", "-s"}, {"-p3.12", "-s"}} {
		args := append([]string{"run"}, flags...)
		settings, err = (UV{}).settings(append(args, path))
		if err != nil || settings["resolution"] != "lowest" {
			t.Fatalf("extensionless script %v: %v/%v", flags, settings, err)
		}
	}
	for _, args := range [][]string{
		{"run", "--module", "missing.py"}, {"run", "-m", "missing.py"},
		{"run", "-vm", "missing.py"},
		{"run", "python", "--script", "missing.py"}, {"run", "python", "-c", "--help"},
		{"tool", "run", "--from", "project", "program", "--script", "missing.py"},
	} {
		if _, err := (UV{}).settings(args); err != nil {
			t.Fatalf("external command arguments inspected: %v: %v", args, err)
		}
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxScriptBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := (UV{}).settings([]string{"run", "--script", path}); err == nil {
		t.Fatal("oversized script was accepted")
	}
}
