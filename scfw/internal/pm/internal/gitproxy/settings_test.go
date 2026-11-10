// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"context"
	"fmt"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGitChildOverridesPreserveMultivaluedSettings(t *testing.T) {
	entries := []gitConfigurationEntry{
		{key: "http.extraheader", value: ""},
		{key: "http.extraheader", value: "X-Example: user's value"},
		{key: "http.extraheader", value: "X-Repeat: same"},
		{key: "http.extraheader", value: "X-Repeat: same"},
		{key: "credential.helper", value: ""},
		{key: "credential.helper", value: "first helper"},
		{key: "credential.helper", value: "second helper"},
	}
	for _, test := range []struct {
		name  string
		count int
	}{
		{name: "count", count: len(entries)},
		{name: "parameters"},
		{name: "mixed", count: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			global := filepath.Join(directory, "global.conf")
			fixture, err := os.ReadFile("testdata/multivalue.conf")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(global, fixture, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GIT_CONFIG_GLOBAL", global)
			t.Setenv("GIT_CONFIG_COUNT", strconv.Itoa(test.count))
			var parameters string
			for index, entry := range entries {
				if index < test.count {
					t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), entry.key)
					t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), entry.value)
				} else {
					parameters += gitParameter(entry.key, entry.value)
				}
			}
			t.Setenv("GIT_CONFIG_PARAMETERS", strings.TrimSpace(parameters))
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			overrides := map[string]string{}
			config := proxy.ClientConfig{URL: "http://127.0.0.1:12345", CACertificatePath: filepath.Join(directory, "ca.pem")}
			if err := settings.ChildOverrides(overrides, config); err != nil {
				t.Fatal(err)
			}
			var environment []string
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if _, replaced := overrides[key]; !replaced {
					environment = append(environment, entry)
				}
			}
			for key, value := range overrides {
				environment = append(environment, key+"="+value)
			}
			for _, key := range []string{"http.extraheader", "credential.helper"} {
				// NUL-delimited output retains empty resets and intentional repeats.
				before, err := runGitConfiguration(settings.executable, directory, os.Environ(), "", "config", "--null", "--get-all", key)
				if err != nil {
					t.Fatal(err)
				}
				after, err := runGitConfiguration(settings.executable, directory, environment, "", "config", "--null", "--get-all", key)
				if err != nil {
					t.Fatal(err)
				}
				if string(after) != string(before) {
					t.Errorf("%s changed through interception: before=%q after=%q", key, before, after)
				}
			}
		})
	}
}

func TestReadOnlyGitSnapshotAndProcessOverrides(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git required")
	}
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "gitconfig"))
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_NO_VERIFY", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Setenv(key, "")
	}
	if err := os.Unsetenv("GIT_SSL_NO_VERIFY"); err != nil {
		t.Fatal(err)
	}
	server, err := proxy.Start(context.Background(), proxy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	fixture, err := os.ReadFile("testdata/git-config.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(string(fixture), server.ClientConfig().CACertificatePath)
	if err := os.WriteFile(filepath.Join(root, "gitconfig"), []byte(content), 0400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "test.keep")
	t.Setenv("GIT_CONFIG_VALUE_0", "unchanged")
	settings, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot remains authoritative if the original configuration changes.
	t.Setenv("GIT_CONFIG_VALUE_0", "changed-after-snapshot")
	for _, test := range []struct {
		address, proxy string
		insecure       bool
	}{
		{"https://elsewhere.example/repo/info/refs", "http://global:secret@global.example:8080", false},
		{"https://specific.example/team/repo/info/refs", "http://specific:secret@specific.example:8080", true},
		{"https://direct.example/repo/info/refs", "", false},
	} {
		target, _ := url.Parse(test.address)
		values, err := settings.Values(target)
		if err != nil {
			t.Fatal(err)
		}
		route, err := settings.RouteValues(target, values)
		if err != nil {
			t.Fatal(err)
		}
		selected := ""
		if route.ProxyURL != nil {
			selected = route.ProxyURL.String()
		}
		if selected != test.proxy || route.TLS.InsecureSkipVerify != test.insecure {
			t.Fatalf("Git settings not URL-scoped for %s", test.address)
		}
	}
	t.Setenv("GIT_CONFIG_VALUE_0", "unchanged")
	config := server.ClientConfig()
	config.AdditionalClients = map[string]proxy.ClientConfig{}
	for name, options := range settings.AdditionalClients() {
		client, err := proxy.Start(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		config.AdditionalClients[name] = client.ClientConfig()
	}
	overrides := map[string]string{}
	if err := settings.ChildOverrides(overrides, config); err != nil {
		t.Fatal(err)
	}
	environment := os.Environ()
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	data, err := runGitConfiguration(settings.executable, root, environment, "", "config", "--get", "test.keep")
	if err != nil || strings.TrimSpace(string(data)) != "unchanged" {
		t.Fatalf("inherited Git overrides lost: %s/%v", data, err)
	}
	data, err = runGitConfiguration(settings.executable, root, environment, "", "config", "--get-urlmatch", "http.proxy", "https://specific.example/team/repo")
	intercepted := false
	for _, client := range config.AdditionalClients {
		if strings.TrimSpace(string(data)) == client.URL {
			intercepted = true
		}
	}
	if err != nil || !intercepted {
		t.Fatalf("URL-specific Git proxy escaped interception: %s/%v", data, err)
	}
	after, err := os.ReadFile(filepath.Join(root, "gitconfig"))
	if err != nil || string(after) != content {
		t.Fatal("Git configuration changed")
	}
	info, err := os.Stat(overrides["GIT_CONFIG_GLOBAL"])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("invocation Git snapshot is not private")
	}
	if os.Getenv("GIT_CONFIG_GLOBAL") != filepath.Join(root, "gitconfig") {
		t.Fatal("parent Git configuration changed")
	}
}
