// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func poetrySettingsFixture(t *testing.T, name, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0400); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReadOnlyPoetryConfigurationPrecedence(t *testing.T) {
	root := t.TempDir()
	config := t.TempDir()
	t.Setenv("POETRY_CONFIG_DIR", config)
	paths := map[string][]byte{}
	paths[filepath.Join(root, "pyproject.toml")] = poetrySettingsFixture(t, "proxy-sources.toml", filepath.Join(root, "pyproject.toml"))
	paths[filepath.Join(root, "poetry.toml")] = poetrySettingsFixture(t, "local-config.toml", filepath.Join(root, "poetry.toml"))
	paths[filepath.Join(config, "config.toml")] = poetrySettingsFixture(t, "global-config.toml", filepath.Join(config, "config.toml"))
	paths[filepath.Join(config, "auth.toml")] = poetrySettingsFixture(t, "auth-config.toml", filepath.Join(config, "auth.toml"))
	command := []string{"-C", root, "install"}
	settings, err := readPoetrySettings(command)
	if err != nil {
		t.Fatal(err)
	}
	if settings.get("certificates", "private", "cert") != "local.pem" || settings.get("certificates", "private", "client-cert") != "client.pem" || settings.get("certificates", "insecure", "cert") != false {
		t.Fatal("configuration precedence or types not preserved")
	}
	t.Setenv("POETRY_CERTIFICATES_PRIVATE_CERT", "environment.pem")
	if settings.get("certificates", "private", "cert") != "environment.pem" {
		t.Fatal("environment does not override merged files")
	}
	for path, before := range paths {
		after, err := os.ReadFile(path)
		if err != nil || !slices.Equal(before, after) {
			t.Fatalf("configuration changed: %s", path)
		}
	}
	empty := filepath.Join(t.TempDir(), "absent")
	t.Setenv("POETRY_CONFIG_DIR", empty)
	if _, err := readPoetrySettings(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Fatal("configuration discovery created user files")
	}
}

func TestPoetryNativeProxyDiscoveryAndBypass(t *testing.T) {
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "PIP_PROXY", "scfw_test_proxy"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	native := pythonproxy.Settings{Proxies: map[string]string{"http": "http://native.example:80", "https": "http://native.example:443"}, Exceptions: []string{"*.internal"}, ExcludeSimple: true}
	for _, test := range []struct {
		key, value string
		native     bool
	}{
		{"http_proxy", "", true}, {"http_proxy", "http://env.example", false}, {"NO_PROXY", "internal.example", false}, {"PIP_PROXY", "http://pip.example", false},
	} {
		t.Run(test.key+test.value, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			called := false
			settings, system, err := discoverPoetryProxies(func() (pythonproxy.Settings, error) { called = true; return native, nil })
			if err != nil || called != test.native {
				t.Fatalf("native discovery=%t, error=%v", called, err)
			}
			if test.native && (settings.HTTPProxy != native.Proxies["http"] || settings.HTTPSProxy != native.Proxies["https"]) {
				t.Fatal("native proxy URLs lost")
			}
			if test.native {
				for _, address := range []string{"https://printer/", "https://host.internal/"} {
					target, _ := url.Parse(address)
					if !system.Bypasses(target) {
						t.Fatal("native bypass lost")
					}
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
	t.Setenv("POETRY_SYSTEM_GIT_CLIENT", "true")
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
	settings, err := readPoetryGitSettings(poetrySettings{workingDirectory: root, values: map[string]any{"system-git-client": true}})
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
		route, err := settings.route(proxy.Request{URL: *target, Header: http.Header{"User-Agent": {"git/2"}}})
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
	overrides := map[string]string{}
	if err := settings.childOverrides(overrides, server.ClientConfig()); err != nil {
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
	if err != nil || strings.TrimSpace(string(data)) != server.ClientConfig().URL {
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
	// File trust in a legacy bundled client needs an explicit compatibility
	// error, while registry-only commands must remain usable.
	t.Setenv("POETRY_CONFIG_DIR", filepath.Join(root, "absent"))
	t.Setenv("POETRY_SYSTEM_GIT_CLIENT", "false")
	legacy := Poetry{version: pm.Version{Major: 1, Minor: 7}, proxyState: &poetryProxyState{}}
	if _, err := legacy.ProxyOptions([]string{"--directory", root, "install"}); err != nil {
		t.Fatalf("unrelated Git trust blocked registry command: %v", err)
	}
	if _, err := legacy.ProxyOptions([]string{"--directory", root, "add", "git+https://elsewhere.example/repo"}); err == nil || !strings.Contains(err.Error(), "experimental.system-git-client") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe/missing compatibility error: %v", err)
	}
}

func TestPoetrySnapshotKeepsSourceTrustAndIgnoresUnusedSettings(t *testing.T) {
	root := t.TempDir()
	t.Setenv("POETRY_CONFIG_DIR", root)
	for _, key := range []string{"GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Setenv(key, "")
	}
	poetrySettingsFixture(t, "proxy-sources.toml", filepath.Join(root, "pyproject.toml"))
	poetrySettingsFixture(t, "global-config.toml", filepath.Join(root, "config.toml"))
	server, err := proxy.Start(context.Background(), proxy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	t.Setenv("REQUESTS_CA_BUNDLE", "/missing/unselected-default-secret.pem")
	t.Setenv("POETRY_CERTIFICATES_PRIVATE_CERT", server.ClientConfig().CACertificatePath)
	t.Setenv("POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT", "")
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}, proxyState: &poetryProxyState{}}
	args := []string{"--directory", root, "install"}
	options, err := manager.ProxyOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	address, _ := url.Parse("https://index.example/python-packages/project/")
	route, err := options.RouteForRequest(proxy.Request{URL: *address})
	if err != nil || route.TLS == nil {
		t.Fatalf("unused settings prevented selected source: %v", err)
	}
	t.Setenv("POETRY_CERTIFICATES_PRIVATE_CERT", "/missing/changed-after-discovery.pem")
	spec, err := manager.ProxyCommand(context.Background(), args, server.ClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvOverrides["POETRY_CERTIFICATES_PRIVATE_CERT"] != server.ClientConfig().CACertificatePath {
		t.Fatal("source path override missing")
	}
	if _, err := options.RouteForRequest(proxy.Request{URL: *address}); err != nil {
		t.Fatal("outbound snapshot re-read parent environment")
	}
	other, _ := url.Parse("https://unconfigured.example/project")
	if _, err := options.RouteForRequest(proxy.Request{URL: *other}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe/missing unconfigured-source error: %v", err)
	}
}
