// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func isolatedEnvironment(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "UV_CONFIG_FILE", "UV_NO_CONFIG", "UV_PROJECT", "UV_WORKING_DIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSL_CLIENT_CERT", "GIT_SSL_CAINFO", "GIT_CONFIG_COUNT", "UV_INSECURE_HOST", "UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UV_NO_SYSTEM_CONFIG", "1")
}

func copyFixture(t *testing.T, fixtureDirectory, name, destination string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixtureDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, content, 0600); err != nil {
		t.Fatal(err)
	}
	return content
}

func TestCommandSelection(t *testing.T) {
	for _, test := range []struct {
		args string
		want bool
	}{
		{"pip install project", true}, {"pip sync requirements.txt", true}, {"pip compile requirements.in", true},
		{"add project", true}, {"sync --locked", true}, {"lock --upgrade", true}, {"remove project", true},
		{"--directory pip --cache-dir install --color always pip --cert cert.pem install project", true},
		{"--directory=install -vv pip --cache-dir=help install project", true},
		{"pip install --index-url https://example.com --python help project", true},
		{"--help", false}, {"pip install --help", false}, {"help pip install", false},
		{"pip list install", false}, {"pip show sync", false}, {"pip uninstall install", false},
		{"cache clean install", false}, {"auth login install", false}, {"python list install", false},
		{"venv install", false}, {"init install", false}, {"--directory install cache clean", false},
		{"--version", false}, {"--directory", false}, {"", false}, {"run echo pip install", true},
		{"run --with project python --help", true}, {"run --help", false},
		{"tool run --from project program --help", true}, {"tool install project", true},
		{"tool upgrade --all", true}, {"tool list install", false},
	} {
		t.Run(test.args, func(t *testing.T) {
			if got := (UV{}).ProxyCommandSupported(strings.Fields(test.args)); got != test.want {
				t.Fatalf("supported = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUpstreamEnvironment(t *testing.T) {
	isolatedEnvironment(t)
	manager := UV{}
	config, err := manager.UpstreamProxy([]string{"sync"})
	if err != nil || config.HTTPProxy != "" || config.HTTPSProxy != "" {
		t.Fatalf("absent proxies = %+v, %v", config, err)
	}
	t.Setenv("http_proxy", "http://lower.example")
	t.Setenv("HTTP_PROXY", "http://user:secret@upper.example:8080")
	t.Setenv("all_proxy", "http://fallback.example")
	t.Setenv("NO_PROXY", ".internal.example,10.0.0.0/8")
	options, err := manager.ProxyOptions([]string{"sync"})
	if err != nil || options.Upstream.HTTPProxy != os.Getenv("HTTP_PROXY") || options.Upstream.HTTPSProxy != os.Getenv("all_proxy") {
		t.Fatalf("upstream = %+v, %v", options.Upstream, err)
	}
	for _, target := range []string{"http://index.example", "https://index.example", "http://127.0.0.1", "http://api.internal.example", "http://10.1.2.3"} {
		parsed, _ := url.Parse(target)
		upstream, err := options.ProxyForURL(parsed)
		bypassed := strings.Contains(target, "internal.example") || strings.Contains(target, "10.1.2.3")
		if err != nil || (upstream == nil) != bypassed {
			t.Fatalf("route for %s: %v, %v", target, upstream, err)
		}
	}
	t.Setenv("HTTP_PROXY", "http://user:secret@host:bad")
	if _, err := manager.UpstreamProxy(nil); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("invalid proxy error = %v", err)
	}
}

func TestSettingsAndInvocationOverrides(t *testing.T) {
	fixtures, _ := filepath.Abs("testdata/config")
	isolatedEnvironment(t)
	directory, _ := os.Getwd()
	userPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "uv", "uv.toml")
	user := copyFixture(t, fixtures, "user.toml", userPath)
	projectPath := filepath.Join(directory, "uv.toml")
	project := copyFixture(t, fixtures, "project.toml", projectPath)
	t.Setenv("HTTP_PROXY", "http://ignored.example")
	t.Setenv("HTTPS_PROXY", "http://ignored.example")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "credential.helper")
	t.Setenv("GIT_CONFIG_VALUE_0", "original-helper")
	manager := UV{executable: "/some/uv"}
	command := []string{"pip", "--cert=original.pem", "install", "--index", "custom=https://cli.example/packages/", "project", "--", "literal"}
	config, err := manager.UpstreamProxy(command)
	if err != nil || config.HTTPProxy != "http://project:secret@project-proxy.example:8080" || config.HTTPSProxy != "http://user:secret@user-proxy.example:8080" || config.NoProxy != "internal.example," {
		t.Fatalf("effective proxies = %+v, %v", config, err)
	}
	ca := proxy.ClientConfig{URL: "http://127.0.0.1:1234", CACertificatePath: filepath.Join(t.TempDir(), "ca.pem")}
	spec, err := manager.ProxyCommand(context.Background(), command, ca)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(command)
	want[1] = "--cert=" + ca.CACertificatePath
	if spec.Executable != manager.executable || !slices.Equal(spec.Args, want) || command[1] != "--cert=original.pem" {
		t.Fatalf("command = %+v, original = %v", spec, command)
	}
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "GIT_CONFIG_VALUE_1"} {
		if spec.EnvOverrides[key] != ca.URL {
			t.Fatalf("%s = %q", key, spec.EnvOverrides[key])
		}
	}
	for _, key := range []string{"SSL_CERT_FILE", "GIT_SSL_CAINFO"} {
		if spec.EnvOverrides[key] != ca.CACertificatePath {
			t.Fatalf("%s = %q", key, spec.EnvOverrides[key])
		}
	}
	if spec.EnvOverrides["GIT_CONFIG_COUNT"] != "2" || spec.EnvOverrides["GIT_CONFIG_KEY_1"] != "http.proxy" || os.Getenv("GIT_CONFIG_COUNT") != "1" || os.Getenv("HTTP_PROXY") != "http://ignored.example" {
		t.Fatal("Git configuration or parent proxy was overwritten")
	}
	invocation, err := readSettings(spec.EnvOverrides["UV_CONFIG_FILE"], false)
	if err != nil || invocation["http-proxy"] != ca.URL || invocation["https-proxy"] != ca.URL || invocation["native-tls"] != true {
		t.Fatalf("invocation settings = %+v, %v", invocation, err)
	}
	wantLinks := []any{filepath.Join(directory, "project-wheels"), filepath.Join(filepath.Dir(userPath), "wheels")}
	if !reflect.DeepEqual(invocation["find-links"], wantLinks) {
		t.Fatalf("merged find-links = %v, want %v", invocation["find-links"], wantLinks)
	}
	for path, original := range map[string][]byte{userPath: user, projectPath: project} {
		content, err := os.ReadFile(path)
		if err != nil || string(content) != string(original) {
			t.Fatalf("persistent config changed: %s", path)
		}
	}
	classifiers, err := manager.PyPIClassifierOptions(command)
	if err != nil || !slices.Contains(classifiers.SimpleIndexURLs, "https://private.example/python/") || !slices.Contains(classifiers.SimpleIndexURLs, "https://pip.example/custom/") || !slices.Contains(classifiers.SimpleIndexURLs, "https://cli.example/packages/") {
		t.Fatalf("classifier settings = %+v, %v", classifiers, err)
	}
}

func TestExplicitConfigAndDiscovery(t *testing.T) {
	fixtures, _ := filepath.Abs("testdata/config")
	isolatedEnvironment(t)
	root, _ := os.Getwd()
	copyFixture(t, fixtures, "pyproject.toml", filepath.Join(root, "pyproject.toml"))
	member := filepath.Join(root, "members", "project")
	if err := os.MkdirAll(member, 0700); err != nil {
		t.Fatal(err)
	}
	copyFixture(t, fixtures, "member.toml", filepath.Join(member, "pyproject.toml"))
	if err := os.Mkdir(filepath.Join(member, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	manager := UV{}
	command := []string{"--directory", filepath.Join(member, "src"), "sync"}
	settings, err := manager.settings(command)
	if err != nil || settings["index-url"] != "https://project.example/custom/" {
		t.Fatalf("workspace settings = %v, %v", settings, err)
	}
	if settings["package"] != nil || !reflect.DeepEqual(settings["constraint-dependencies"], []any{"project<2"}) {
		t.Fatalf("project settings were not preserved for standalone config: %v", settings)
	}
	explicit := filepath.Join(root, "explicit.toml")
	copyFixture(t, fixtures, "project.toml", explicit)
	t.Setenv("UV_CONFIG_FILE", explicit)
	settings, err = manager.settings(command)
	if err != nil || settings["http-proxy"] == nil || settings["native-tls"] != nil {
		t.Fatalf("explicit config should replace discovery: %v, %v", settings, err)
	}
	t.Setenv("UV_CONFIG_FILE", "")
	t.Setenv("UV_NO_CONFIG", "1")
	settings, err = manager.settings(command)
	if err != nil || len(settings) != 0 {
		t.Fatalf("no-config = %v, %v", settings, err)
	}
	t.Setenv("UV_NO_CONFIG", "")
	invalid := filepath.Join(root, "invalid.toml")
	copyFixture(t, fixtures, "invalid.toml", invalid)
	if _, err := manager.UpstreamProxy([]string{"--config-file", invalid, "lock"}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("config error = %v", err)
	}
	project, err := manager.ProjectDirectory([]string{"--directory", "members", "--project", "project", "sync"})
	if err != nil || project != member {
		t.Fatalf("project directory = %s, %v", project, err)
	}
}

func TestWorkspaceGlobs(t *testing.T) {
	for _, test := range []struct {
		pattern, path string
		want          bool
	}{
		{"members/*", "members/project", true}, {"members/*", "members/nested/project", false},
		{"members/**", "members/nested/project", true}, {"**/project", "members/nested/project", true},
		{"**/project", "project", true}, {"members/**/project", "other/project", false},
	} {
		if got := matchesWorkspace([]any{test.pattern}, test.path); got != test.want {
			t.Errorf("%s matching %s = %v", test.pattern, test.path, got)
		}
	}
}

func TestProxyModeRequiredOnlyForPackageOperations(t *testing.T) {
	manager, err := NewUV(context.Background(), "uv", "/custom/uv")
	if err != nil || manager.Executable() != "/custom/uv" {
		t.Fatal(manager, err)
	}
	if _, err := manager.ResolveInstallTargets(context.Background(), []string{"sync"}); err == nil {
		t.Fatal("package operation allowed without proxy mode")
	}
	if targets, err := manager.ResolveInstallTargets(context.Background(), []string{"cache", "clean"}); err != nil || targets.Len() != 0 {
		t.Fatal(targets, err)
	}
	if _, err := NewUV(context.Background(), "nonexistent-scfw-uv", ""); err == nil {
		t.Fatal("missing executable accepted")
	}
}
