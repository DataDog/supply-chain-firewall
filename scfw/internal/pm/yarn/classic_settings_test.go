// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateYarnEnvironment removes the host's Yarn, npm, proxy, and trust
// settings and enters <root>/parent/project, with HOME and PREFIX under root.
func isolateYarnEnvironment(t *testing.T) string {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(lower, "yarn_") || strings.HasSuffix(lower, "_proxy") ||
			lower == "proxy" || key == "NODE_EXTRA_CA_CERTS" || key == "GIT_SSL_CAINFO" || key == "PREFIX" || key == "DESTDIR" {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("PREFIX", filepath.Join(root, "prefix"))
	project := filepath.Join(root, "parent", "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	return root
}

// testdataDir is absolute because tests change directory before reading fixtures.
var testdataDir, _ = filepath.Abs("testdata")

// writeYarnFixture copies testdata/<fixture> to path, substituting args into
// .tmpl fixtures.
func writeYarnFixture(t *testing.T, path, fixture string, args ...any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, fixture))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.HasSuffix(fixture, ".tmpl") {
		content = fmt.Sprintf(content, args...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestClassicUpstreamPrecedence(t *testing.T) {
	type source func(t *testing.T, root string)
	file := func(dir, name, fixture, value string) source {
		return func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, dir, name), fixture, value)
		}
	}
	env := func(key, value string) source {
		return func(t *testing.T, _ string) { t.Setenv(key, value) }
	}
	project, parent, home := "parent/project", "parent", "home"
	for _, test := range []struct {
		name    string
		command []string
		sources []source
		https   string
	}{
		{"cli beats rc-arg", []string{"--https-proxy=http://cli:1", "add", "x"},
			[]source{file(project, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://rc-arg:1")}, "http://cli:1"},
		{"cli after the command", []string{"add", "x", "--https-proxy", "http://cli:1"},
			[]source{env("YARN_HTTPS_PROXY", "http://env:1")}, "http://cli:1"},
		{"rc-arg beats YARN_HTTPS_PROXY", nil, []source{
			file(project, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://rc-arg:1"), env("YARN_HTTPS_PROXY", "http://env:1"),
		}, "http://rc-arg:1"},
		// Yarn merges rc-args from the cwd chain first and the home file last.
		{"home rc-arg beats project rc-arg", nil, []source{
			file(project, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://project-arg:1"),
			file(home, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://home-arg:1"),
		}, "http://home-arg:1"},
		{"YARN_HTTPS_PROXY beats project .yarnrc", nil, []source{
			env("YARN_HTTPS_PROXY", "http://env:1"), file(project, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1"),
		}, "http://env:1"},
		{"lowercase yarn_https_proxy", nil, []source{env("yarn_https_proxy", "http://env:1")}, "http://env:1"},
		{"project beats home .yarnrc", nil, []source{
			file(project, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1"),
			file(home, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://home:1"),
		}, "http://project:1"},
		// Yarn reads the cwd, home, and global files before parent directories.
		{"home beats parent .yarnrc", nil, []source{
			file(parent, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://parent:1"),
			file(home, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://home:1"),
		}, "http://home:1"},
		{"parent .yarnrc", nil, []source{file(parent, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://parent:1")}, "http://parent:1"},
		{"global yarnrc", nil, []source{file("prefix/etc", "yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://global:1")}, "http://global:1"},
		{"home .yarnrc beats npm_config_https_proxy", nil, []source{
			file(home, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://home:1"), env("npm_config_https_proxy", "http://npm-env:1"),
		}, "http://home:1"},
		{"npm_config_https_proxy beats project .npmrc", nil, []source{
			env("npm_config_https_proxy", "http://npm-env:1"), file(project, ".npmrc", "yarnrc/https-proxy.npmrc.tmpl", "http://npmrc:1"),
		}, "http://npm-env:1"},
		{".npmrc https-proxy beats .yarnrc proxy", nil, []source{
			file(project, ".npmrc", "yarnrc/https-proxy.npmrc.tmpl", "http://npmrc:1"),
			file(project, ".yarnrc", "yarnrc/proxy.yarnrc.tmpl", "http://yarn-proxy:1"),
		}, "http://npmrc:1"},
		{"proxy only is used for https", nil, []source{file(project, ".yarnrc", "yarnrc/proxy.yarnrc.tmpl", "http://yarn-proxy:1")}, "http://yarn-proxy:1"},
		{"HTTPS_PROXY beats https_proxy", nil, []source{env("HTTPS_PROXY", "http://upper:1"), env("https_proxy", "http://lower:1")}, "http://upper:1"},
		{"https_proxy beats HTTP_PROXY", nil, []source{env("https_proxy", "http://lower:1"), env("HTTP_PROXY", "http://http:1")}, "http://lower:1"},
		{"HTTP_PROXY is used for https", nil, []source{env("HTTP_PROXY", "http://http:1")}, "http://http:1"},
		{"ALL_PROXY is ignored", nil, []source{env("ALL_PROXY", "http://all:1")}, ""},
		{"YARN_HTTP_PROXY is ignored", nil, []source{env("YARN_HTTP_PROXY", "http://yarn-http:1")}, ""},
		{"https-proxy false disables the environment", nil, []source{
			file(project, ".yarnrc", "yarnrc/disabled.yarnrc", ""), env("HTTPS_PROXY", "http://upper:1"),
		}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			for _, add := range test.sources {
				add(t, root)
			}
			config, err := fakeYarn(t, "1.22.22").UpstreamProxy(test.command)
			if err != nil {
				t.Fatal(err)
			}
			if config.HTTPSProxy != test.https {
				t.Fatalf("HTTPSProxy = %q, want %q", config.HTTPSProxy, test.https)
			}
		})
	}
}

func TestClassicUpstreamHTTPProxy(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "home", ".yarnrc"), "yarnrc/proxy.yarnrc.tmpl", "http://yarn-proxy:1")
	t.Setenv("HTTP_PROXY", "http://env:1")
	config, err := fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err != nil || config.HTTPProxy != "http://yarn-proxy:1" {
		t.Fatalf("HTTPProxy = %q (error %v)", config.HTTPProxy, err)
	}
}

func TestClassicUpstreamNoProxyOnlyForEnvironment(t *testing.T) {
	root := isolateYarnEnvironment(t)
	t.Setenv("HTTPS_PROXY", "http://upper:1")
	t.Setenv("NO_PROXY", "registry.yarnpkg.com")
	config, err := fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err != nil || config.HTTPSProxy != "http://upper:1" || config.NoProxy != "registry.yarnpkg.com" {
		t.Fatalf("config = %+v (error %v), want the environment's proxy and bypass list", config, err)
	}
	// Yarn passes a configured proxy to its HTTP client, which then ignores NO_PROXY.
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1")
	config, err = fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err != nil || config.HTTPSProxy != "http://project:1" || config.NoProxy != "" {
		t.Fatalf("config = %+v (error %v), want the configured proxy without a bypass list", config, err)
	}
}

func TestClassicUpstreamHonorsCwdOption(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", "pkg", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://pkg:1")
	// Yarn Classic accepts --cwd anywhere before "--".
	for _, command := range [][]string{{"--cwd", "pkg", "add", "x"}, {"add", "x", "--cwd", "pkg"}, {"add", "x", "--cwd=pkg"}} {
		config, err := fakeYarn(t, "1.22.22").UpstreamProxy(command)
		if err != nil || config.HTTPSProxy != "http://pkg:1" {
			t.Fatalf("%q: HTTPSProxy = %q (error %v)", command, config.HTTPSProxy, err)
		}
	}
}

// `yarn workspace` re-runs Yarn without SCFW's proxy options, so an rc-arg
// proxy would win over the environment there.
func TestClassicRefusesWorkspaceWithRcArgProxy(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", ".yarnrc"), "yarnrc/rc-arg.yarnrc.tmpl", "http://rc-arg:1")
	if _, err := fakeYarn(t, "1.22.22").UpstreamProxy([]string{"add", "x"}); err != nil {
		t.Fatalf("direct commands still work: %v", err)
	}
	_, err := fakeYarn(t, "1.22.22").ProxyOptions([]string{"workspace", "a", "add", "x"})
	if err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("error = %v, want the workspace refusal", err)
	}
}

func TestClassicUpstreamRejectsInvalidURLWithoutCredentials(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/invalid.yarnrc")
	_, err := fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error = %v, want a credential-free error", err)
	}
}
