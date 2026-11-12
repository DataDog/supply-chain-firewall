// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/pelletier/go-toml/v2"
)

// readPoetryFixture groups small configuration cases while keeping templates,
// executable scripts, and certificate material in their original formats.
func readPoetryFixture(name string) ([]byte, error) {
	data, err := os.ReadFile("testdata/configurations.toml")
	if err != nil {
		return nil, err
	}
	var cases map[string]string
	if err := toml.Unmarshal(data, &cases); err != nil {
		return nil, err
	}
	if value, ok := cases[name]; ok {
		return []byte(value), nil
	}
	return os.ReadFile(filepath.Join("testdata", name))
}

func poetrySettingsFixture(t *testing.T, name, path string) []byte {
	t.Helper()
	data, err := readPoetryFixture(name)
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

func TestPoetryConfigurationDirectoryUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	start := filepath.Join(root, "start")
	work := filepath.Join(root, "work")
	project := filepath.Join(root, "project")
	global := filepath.Join(root, "global")
	paths := map[string][]byte{}
	for _, directory := range []string{start, work, project, filepath.Join(global, "leaf")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{filepath.Join(work, "config"), filepath.Join(work, "{cache-dir}"), filepath.Join(work, "config-home", "pypoetry"), global} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for name, fixture := range map[string]string{"config.toml": "global-config.toml", "auth.toml": "auth-config.toml"} {
			path := filepath.Join(directory, name)
			paths[path] = poetrySettingsFixture(t, fixture, path)
		}
	}
	for _, directory := range []string{start, project} {
		config := filepath.Join(directory, "config")
		if err := os.Mkdir(config, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(config, "config.toml")
		paths[path] = poetrySettingsFixture(t, "disabled-private-trust.toml", path)
	}
	path := filepath.Join(project, "pyproject.toml")
	paths[path] = poetrySettingsFixture(t, "proxy-project.toml", path)
	if err := os.Symlink(filepath.Join(global, "leaf"), filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(start)
	for _, test := range []struct {
		name, directory string
		xdg, missing    bool
	}{
		{name: "relative", directory: "config"},
		{name: "literal placeholders", directory: "{cache-dir}"},
		{name: "symlink parent", directory: "link/.."},
		{name: "absolute symlink parent", directory: work + "/link/.."},
		{name: "relative XDG", directory: "config-home", xdg: true},
		{name: "missing parent", directory: "missing/../config", missing: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.xdg {
				if runtime.GOOS == "darwin" {
					t.Skip("Poetry ignores XDG_CONFIG_HOME on macOS")
				}
				t.Setenv("POETRY_CONFIG_DIR", "")
				t.Setenv("XDG_CONFIG_HOME", test.directory)
			} else {
				t.Setenv("POETRY_CONFIG_DIR", test.directory)
			}
			settings, err := readPoetrySettings([]string{"--directory", work, "--project", "../project", "install"})
			if err != nil {
				t.Fatal(err)
			}
			if test.missing {
				if settings.get("certificates", "private", "cert") != nil {
					t.Fatal("traversed a nonexistent configuration directory")
				}
				return
			}
			if settings.get("certificates", "private", "cert") != "auth.pem" || settings.get("certificates", "private", "client-cert") != "client.pem" || settings.get("http-basic", "private", "password") != "configuration-secret" {
				t.Fatal("did not load global configuration and authentication from the working directory")
			}
		})
	}
	for path, before := range paths {
		after, err := os.ReadFile(path)
		if err != nil || !slices.Equal(before, after) {
			t.Fatal("configuration or authentication changed")
		}
	}
	if _, err := os.Stat(filepath.Join(work, "missing")); !os.IsNotExist(err) {
		t.Fatal("created a missing configuration directory")
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

func TestPoetrySnapshotKeepsSourceTrustAndIgnoresUnusedSettings(t *testing.T) {
	root := t.TempDir()
	t.Setenv("POETRY_CONFIG_DIR", root)
	for _, key := range []string{"GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Setenv(key, "")
	}
	poetrySettingsFixture(t, "proxy-sources.toml", filepath.Join(root, "pyproject.toml"))
	poetrySettingsFixture(t, "global-config.toml", filepath.Join(root, "config.toml"))
	config := poetryInvocationConfig(t)
	t.Setenv("REQUESTS_CA_BUNDLE", "/missing/unselected-default-secret.pem")
	t.Setenv("POETRY_CERTIFICATES_PRIVATE_CERT", config.CACertificatePath)
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
	spec, err := manager.ProxyCommand(context.Background(), args, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvOverrides["POETRY_CERTIFICATES_PRIVATE_CERT"] != config.CACertificatePath {
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

func TestPoetryCertificateConfigurationReferences(t *testing.T) {
	root := isolatedPoetryProject(t)
	config := poetryInvocationConfig(t)
	data, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ca.pem"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POETRY_CACHE_DIR", root)
	poetrySettingsFixture(t, "certificate-references.toml", filepath.Join(root, "poetry.toml"))
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"--directory", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://index.example/simple/project/")
	if _, err := options.RouteForRequest(proxy.Request{URL: *target}); err != nil {
		t.Fatalf("nested certificate reference was not resolved: %v", err)
	}
	settings, err := readPoetrySettings([]string{"--directory", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	if got := settings.certificatePath("{virtualenvs.path}/ca.pem"); got != filepath.Join(root, "virtualenvs", "ca.pem") {
		t.Fatalf("default configuration reference=%q", got)
	}
	if got := settings.certificatePath("{unknown.setting}/ca.pem"); !strings.Contains(got, "{unknown.setting}") {
		t.Fatal("unknown reference was silently removed")
	}
	settings.values["cycle"] = "{cycle}"
	if got := settings.get("cycle"); !strings.Contains(got.(string), "{cycle}") {
		t.Fatal("cyclic reference did not remain bounded")
	}
}

func TestPoetryHTTPDoesNotLoadUnusedTrust(t *testing.T) {
	root := isolatedPoetryProject(t)
	t.Setenv("REQUESTS_CA_BUNDLE", "/unused/secret.pem")
	for _, upstream := range []string{"", "http://upstream.example:8080", "https://upstream.example:443"} {
		t.Run(upstream, func(t *testing.T) {
			t.Setenv("http_proxy", upstream)
			manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
			options, err := manager.ProxyOptions([]string{"--directory", root, "install"})
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse("http://index.example/simple/project/")
			_, err = options.RouteForRequest(proxy.Request{URL: *target})
			if strings.HasPrefix(upstream, "https:") {
				if err == nil || strings.Contains(err.Error(), "secret") {
					t.Fatalf("HTTPS proxy ignored required trust or leaked its path: %v", err)
				}
			} else if err != nil {
				t.Fatalf("HTTP-only route loaded unused trust: %v", err)
			}
			target, _ = url.Parse("https://index.example/simple/project/")
			if _, err := options.RouteForRequest(proxy.Request{URL: *target}); err == nil {
				t.Fatal("HTTPS destination ignored invalid required trust")
			}
		})
	}
}
