// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// isolatedNpm removes the host's npm, proxy, and trust settings. PREFIX points
// the default global npmrc at an empty directory, the npm counterpart of
// PIP_CONFIG_FILE=os.DevNull.
func isolatedNpm(t *testing.T) Npm {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasSuffix(lower, "_proxy") || lower == "proxy" ||
			slices.Contains([]string{"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "PREFIX", "DESTDIR"}, key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("PREFIX", filepath.Join(root, "prefix"))
	t.Chdir(t.TempDir())
	return Npm{executable: "npm"}
}

func TestSettingsFromEnvironmentAndOptions(t *testing.T) {
	for _, test := range []struct {
		name                      string
		env                       [][2]string
		args                      []string
		https, http, noProxyParts string
		strictSSL                 bool
	}{
		{name: "HTTPS_PROXY serves both schemes", env: [][2]string{{"HTTPS_PROXY", "http://corp:1"}},
			https: "http://corp:1", http: "http://corp:1", strictSSL: true},
		{name: "HTTP_PROXY serves only http", env: [][2]string{{"HTTP_PROXY", "http://h:2"}},
			http: "http://h:2", strictSSL: true},
		{name: "bare PROXY serves only http", env: [][2]string{{"PROXY", "http://bare:3"}},
			http: "http://bare:3", strictSSL: true},
		{name: "config proxy beats environment", env: [][2]string{{"npm_config_proxy", "http://p:3"}, {"HTTPS_PROXY", "http://corp:1"}},
			https: "http://p:3", http: "http://p:3", strictSSL: true},
		{name: "config https-proxy beats config proxy", env: [][2]string{{"npm_config_proxy", "http://p:3"}, {"npm_config_https_proxy", "http://hp:4"}},
			https: "http://hp:4", http: "http://hp:4", strictSSL: true},
		{name: "proxy=false is unset", env: [][2]string{{"npm_config_proxy", "false"}, {"HTTPS_PROXY", "http://corp:1"}},
			https: "http://corp:1", http: "http://corp:1", strictSSL: true},
		{name: "options beat environment", env: [][2]string{{"npm_config_https_proxy", "http://env:6"}},
			args: []string{"install", "x", "--https-proxy", "http://cli:5"}, https: "http://cli:5", http: "http://cli:5", strictSSL: true},
		{name: "last option wins", args: []string{"--https-proxy=http://a:1", "--https-proxy=http://b:2"},
			https: "http://b:2", http: "http://b:2", strictSSL: true},
		{name: "last environment variant wins", env: [][2]string{{"NPM_CONFIG_HTTPS_PROXY", "http://first:1"}, {"npm_config_https_proxy", "http://last:2"}},
			https: "http://last:2", http: "http://last:2", strictSSL: true},
		{name: "dash environment variant", env: [][2]string{{"npm_config_https-proxy", "http://dash:1"}},
			https: "http://dash:1", http: "http://dash:1", strictSSL: true},
		{name: "empty environment value is ignored", env: [][2]string{{"npm_config_https_proxy", ""}, {"HTTPS_PROXY", "http://corp:1"}},
			https: "http://corp:1", http: "http://corp:1", strictSSL: true},
		{name: "noproxy union", env: [][2]string{{"npm_config_noproxy", "a.test"}, {"NO_PROXY", "b.test"}},
			noProxyParts: "a.test,b.test", strictSSL: true},
		{name: "env no_proxy fallback", env: [][2]string{{"no_proxy", "b.test"}}, noProxyParts: "b.test", strictSSL: true},
		{name: "strict-ssl from environment", env: [][2]string{{"npm_config_strict_ssl", "false"}}},
		{name: "strict-ssl from options", args: []string{"--no-strict-ssl"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			for _, pair := range test.env {
				t.Setenv(pair[0], pair[1])
			}
			result, err := manager.settings(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if result.HTTPS != test.https || result.HTTP != test.http || result.StrictSSL != test.strictSSL {
				t.Fatalf("https=%q http=%q strictSSL=%v", result.HTTPS, result.HTTP, result.StrictSSL)
			}
			for part := range strings.SplitSeq(test.noProxyParts, ",") {
				if !slices.Contains(strings.Split(result.NoProxy, ","), part) && part != "" {
					t.Fatalf("noproxy %q lacks %q", result.NoProxy, part)
				}
			}
			if test.noProxyParts == "" && result.NoProxy != "" {
				t.Fatalf("noproxy = %q", result.NoProxy)
			}
		})
	}
}

// npm treats null as unset; `npm config set proxy null` writes proxy=null.
func TestSettingsTreatNullAsUnset(t *testing.T) {
	for _, test := range []struct {
		name  string
		npmrc string
		env   [][2]string
		args  []string
	}{
		{name: "npmrc", npmrc: "proxy=null\nhttps-proxy=null\nnoproxy=null\nca=null\ncafile=null\n"},
		{name: "environment", env: [][2]string{{"npm_config_proxy", "null"}, {"npm_config_https_proxy", "null"}, {"npm_config_ca", "null"}}},
		{name: "options", args: []string{"--proxy=null", "--https-proxy", "null", "--cafile=null"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			t.Setenv("HTTPS_PROXY", "http://corp:1")
			t.Setenv("NO_PROXY", "internal.test")
			for _, pair := range test.env {
				t.Setenv(pair[0], pair[1])
			}
			writeNpmFixture(t, ".npmrc", test.npmrc)
			result, err := manager.settings(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if result.HTTPS != "http://corp:1" || result.NoProxy != "internal.test" || len(result.CA) != 0 || result.CAFile != "" {
				t.Fatalf("https=%q noproxy=%q ca=%q cafile=%q, want the environment fallbacks and no CA", result.HTTPS, result.NoProxy, result.CA, result.CAFile)
			}
			if _, err := manager.ProxyOptions(test.args); err != nil {
				t.Fatalf("ProxyOptions: %v", err)
			}
		})
	}
}

func TestUpstreamProxyMatchesSettings(t *testing.T) {
	manager := isolatedNpm(t)
	t.Setenv("npm_config_https_proxy", "http://hp:4")
	t.Setenv("HTTP_PROXY", "http://h:2")
	t.Setenv("NO_PROXY", "internal.test")
	config, err := manager.UpstreamProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.HTTPSProxy != "http://hp:4" || config.HTTPProxy != "http://hp:4" || config.NoProxy != "internal.test" {
		t.Fatalf("upstream = %+v", config)
	}
}

// Only the proxies npm selects are validated: npm never parses the others.
func TestUnusedInvalidProxyVariablesAreIgnored(t *testing.T) {
	for _, unused := range [][2]string{{"http_proxy", "corp:8080"}, {"PROXY", "not a url"}} {
		t.Run(unused[0], func(t *testing.T) {
			manager := isolatedNpm(t)
			t.Setenv("https_proxy", "http://corp:3128")
			t.Setenv(unused[0], unused[1])
			config, err := manager.UpstreamProxy([]string{"install"})
			if err != nil {
				t.Fatalf("UpstreamProxy: %v", err)
			}
			if config.HTTPSProxy != "http://corp:3128" || config.HTTPProxy != "http://corp:3128" {
				t.Fatalf("upstream = %+v", config)
			}
			if _, err := manager.ProxyOptions([]string{"install"}); err != nil {
				t.Fatalf("ProxyOptions: %v", err)
			}
		})
	}
}

func TestInvalidUpstreamNeverBecomesDirect(t *testing.T) {
	for _, test := range []struct{ key, value string }{
		{"npm_config_https_proxy", "http://u:secret@[bad"},
		{"npm_config_https_proxy", "127.0.0.1:3128"},
		{"npm_config_proxy", "socks5://h:1"},
		{"HTTP_PROXY", "127.0.0.1:3128"},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			manager := isolatedNpm(t)
			t.Setenv(test.key, test.value)
			_, upstreamErr := manager.UpstreamProxy([]string{"install"})
			_, optionsErr := manager.ProxyOptions([]string{"install"})
			for _, err := range []error{upstreamErr, optionsErr} {
				if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "h:1") || strings.Contains(err.Error(), "3128") {
					t.Fatalf("error = %v", err)
				}
			}
		})
	}
}

func TestReadNpmrc(t *testing.T) {
	env := map[string]string{"CORP": "http://env:1", "SCOPE": "lab"}
	for _, test := range []struct {
		fixture string
		want    npmConfig
		absent  []string
	}{
		// Quotes survive when an inline comment follows them, as in npm.
		{"crlf-bom.npmrc", npmConfig{"https-proxy": {`"http://q:1"`}, "proxy": {"http://crlf:2"}}, nil},
		{"cr-only.npmrc", npmConfig{"https-proxy": {"http://cr:1"}, "proxy": {"http://cr2:2"}}, nil},
		{"syntax.npmrc", npmConfig{
			"https-proxy": {"http://sp:1"}, "proxy": {"http://q:1/;x"}, "noproxy": {"http://c:1"},
			"registry": {"http://h:1/"}, "cafile": {"/single/quoted.pem"}, "ca": {"a\nb\"c"},
			"globalconfig": {"a;b"}, "userconfig": {`"http://u:1`}, "strict-ssl": {"true"}, "prefix": {"last"},
		}, nil},
		{"expansion.npmrc", npmConfig{
			"https-proxy": {"http://env:1"}, "proxy": {"${UNSET}"}, "noproxy": {"xy"},
			"registry": {"http://r/${CORP}"}, "@lab:registry": {"http://k:1/"},
		}, nil},
		{"sections.npmrc", npmConfig{"https-proxy": {"http://top:1"}}, []string{"proxy"}},
		{"arrays.npmrc", npmConfig{"noproxy": {"a.test", "b.test"}, "ca": {"x", "y"}}, nil},
		{"credentials.npmrc", npmConfig{}, []string{"https-proxy", "_authToken"}},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			got := readNpmrc([]byte(readNpmFixture(t, filepath.Join("npmrc", test.fixture))), env)
			for key, values := range test.want {
				if !slices.Equal(got[key], values) {
					t.Errorf("%s = %q, want %q", key, got[key], values)
				}
			}
			for _, key := range test.absent {
				if _, found := got[key]; found {
					t.Errorf("%s must not be set: %q", key, got[key])
				}
			}
		})
	}
}

func TestSettingsReadErrorsAreFixed(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, path string){
		"fifo": func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"oversized": func(t *testing.T, path string) {
			writeNpmFixture(t, path, "proxy=http://p:1\n"+strings.Repeat("#", 8<<20))
		},
	} {
		t.Run(name, func(t *testing.T) {
			manager := isolatedNpm(t)
			writeNpmFixture(t, "package.json", "{}")
			prepare(t, ".npmrc")
			_, err := manager.settings(nil)
			if err == nil || err.Error() != "could not read npm configuration" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSettingsMergesNpmrcLayersPerKey(t *testing.T) {
	manager := isolatedNpm(t)
	writeNpmFixture(t, "package.json", "{}")
	writeNpmFixture(t, ".npmrc", "proxy=http://proj:2\nnoproxy=internal.test\n")
	writeNpmFixture(t, filepath.Join(os.Getenv("HOME"), ".npmrc"), "https-proxy=http://user:1\nproxy=http://user-proxy:9\n")
	result, err := manager.settings(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.HTTPS != "http://user:1" || result.NoProxy != "internal.test" {
		t.Fatalf("https=%q noproxy=%q", result.HTTPS, result.NoProxy)
	}
	t.Setenv("npm_config_https_proxy", "http://env:3")
	if result, _ = manager.settings(nil); result.HTTPS != "http://env:3" {
		t.Fatalf("environment must beat npmrc files: %q", result.HTTPS)
	}
	if result, _ = manager.settings([]string{"--https-proxy=http://cli:4"}); result.HTTPS != "http://cli:4" {
		t.Fatalf("options must beat environment: %q", result.HTTPS)
	}
}

// projectProxy returns the https-proxy npm would use for args from cwd.
func projectProxy(t *testing.T, manager Npm, args ...string) string {
	t.Helper()
	result, err := manager.settings(args)
	if err != nil {
		t.Fatal(err)
	}
	return result.HTTPS
}

func TestSettingsProjectLocation(t *testing.T) {
	t.Run("walks up to package.json", func(t *testing.T) {
		manager := isolatedNpm(t)
		root, _ := os.Getwd()
		writeNpmFixture(t, filepath.Join(root, "package.json"), "{}")
		writeNpmFixture(t, filepath.Join(root, ".npmrc"), "https-proxy=http://root:1\n")
		writeNpmFixture(t, filepath.Join(root, "a", "b", ".npmrc"), "https-proxy=http://cwd:1\n")
		t.Chdir(filepath.Join(root, "a", "b"))
		if got := projectProxy(t, manager); got != "http://root:1" {
			t.Fatalf("got %q; a .npmrc in cwd is ignored when the project is above it", got)
		}
	})
	t.Run("nearest node_modules wins", func(t *testing.T) {
		manager := isolatedNpm(t)
		root, _ := os.Getwd()
		writeNpmFixture(t, filepath.Join(root, "package.json"), "{}")
		writeNpmFixture(t, filepath.Join(root, ".npmrc"), "https-proxy=http://root:1\n")
		writeNpmFixture(t, filepath.Join(root, "a", "node_modules", ".keep"), "")
		writeNpmFixture(t, filepath.Join(root, "a", ".npmrc"), "https-proxy=http://a:1\n")
		t.Chdir(filepath.Join(root, "a"))
		if got := projectProxy(t, manager); got != "http://a:1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("prefix options are relative to cwd", func(t *testing.T) {
		manager := isolatedNpm(t)
		root, _ := os.Getwd()
		writeNpmFixture(t, filepath.Join(root, "a", "package.json"), "{}")
		writeNpmFixture(t, filepath.Join(root, "a", ".npmrc"), "https-proxy=http://a:1\n")
		writeNpmFixture(t, filepath.Join(root, "x", ".npmrc"), "https-proxy=http://x:1\n")
		t.Chdir(filepath.Join(root, "a"))
		for _, args := range [][]string{{"--prefix", "../x"}, {"-C", "../x"}, {"--prefix=../x", "install"}} {
			if got := projectProxy(t, manager, args...); got != "http://x:1" {
				t.Fatalf("%q: got %q", args, got)
			}
		}
		t.Setenv("npm_config_prefix", filepath.Join(root, "x"))
		if got := projectProxy(t, manager); got != "http://a:1" {
			t.Fatalf("an environment prefix must not move the project: %q", got)
		}
	})
	t.Run("no project marker uses cwd", func(t *testing.T) {
		manager := isolatedNpm(t)
		writeNpmFixture(t, ".npmrc", "https-proxy=http://cwd:1\n")
		if got := projectProxy(t, manager); got != "http://cwd:1" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestSettingsSkipsProjectNpmrcForGlobal(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		env  [2]string
		skip bool
	}{
		{name: "-g", args: []string{"-g", "install"}, skip: true},
		{name: "--global", args: []string{"install", "--global"}, skip: true},
		{name: "--global=true", args: []string{"--global=true"}, skip: true},
		{name: "--global true", args: []string{"--global", "true", "install"}, skip: true},
		{name: "--global=false", args: []string{"--global=false"}},
		{name: "--global false", args: []string{"--global", "false", "install"}},
		{name: "-g false", args: []string{"-g", "false", "install"}},
		{name: "--no-global overrides env", args: []string{"--no-global"}, env: [2]string{"npm_config_global", "true"}},
		{name: "--location=global", args: []string{"--location=global"}, skip: true},
		{name: "env global", env: [2]string{"npm_config_global", "true"}, skip: true},
		{name: "env location", env: [2]string{"npm_config_location", "global"}, skip: true},
		{name: "local", args: []string{"install"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			if test.env[0] != "" {
				t.Setenv(test.env[0], test.env[1])
			}
			writeNpmFixture(t, "package.json", "{}")
			writeNpmFixture(t, ".npmrc", "https-proxy=http://proj:1\n")
			if got := projectProxy(t, manager, test.args...); (got == "") != test.skip {
				t.Fatalf("project proxy = %q, skip = %v", got, test.skip)
			}
		})
	}
	t.Run("npmrc global does not skip", func(t *testing.T) {
		manager := isolatedNpm(t)
		writeNpmFixture(t, "package.json", "{}")
		writeNpmFixture(t, ".npmrc", "https-proxy=http://proj:1\n")
		writeNpmFixture(t, filepath.Join(os.Getenv("HOME"), ".npmrc"), "global=true\n")
		if got := projectProxy(t, manager); got != "http://proj:1" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestSettingsUserConfigLocation(t *testing.T) {
	manager := isolatedNpm(t)
	cwd, _ := os.Getwd()
	writeNpmFixture(t, filepath.Join(os.Getenv("HOME"), ".npmrc"), "https-proxy=http://home:1\nuserconfig="+filepath.Join(cwd, "chained.npmrc")+"\n")
	writeNpmFixture(t, filepath.Join(cwd, "chained.npmrc"), "https-proxy=http://chained:1\n")
	writeNpmFixture(t, filepath.Join(cwd, "u.npmrc"), "https-proxy=http://u:1\n")
	if got := projectProxy(t, manager); got != "http://home:1" {
		t.Fatalf("default user config: %q (a userconfig inside it must be ignored)", got)
	}
	if got := projectProxy(t, manager, "--userconfig", "u.npmrc"); got != "http://u:1" {
		t.Fatalf("--userconfig: %q", got)
	}
	t.Setenv("npm_config_userconfig", "u.npmrc")
	if got := projectProxy(t, manager); got != "http://u:1" {
		t.Fatalf("npm_config_userconfig relative to cwd: %q", got)
	}
	t.Setenv("npm_config_userconfig", "")
	writeNpmFixture(t, filepath.Join(cwd, ".npmrc"), "userconfig=u.npmrc\n")
	if got := projectProxy(t, manager); got != "http://u:1" {
		t.Fatalf("project userconfig: %q", got)
	}
	t.Setenv("HOME", "")
	if err := os.Remove(filepath.Join(cwd, ".npmrc")); err != nil {
		t.Fatal(err)
	}
	if got := projectProxy(t, manager); got != "" {
		t.Fatalf("an empty HOME has no user config: %q", got)
	}
}

func TestSettingsGlobalConfigLocation(t *testing.T) {
	setter := func(t *testing.T, dir, name string) string {
		path := filepath.Join(dir, name+".npmrc")
		writeNpmFixture(t, path, "https-proxy=http://"+name+":1\n")
		return path
	}
	t.Run("default under PREFIX", func(t *testing.T) {
		manager := isolatedNpm(t)
		writeNpmFixture(t, filepath.Join(os.Getenv("PREFIX"), "etc", "npmrc"), "https-proxy=http://prefix:1\n")
		if got := projectProxy(t, manager); got != "http://prefix:1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("default from node under DESTDIR", func(t *testing.T) {
		manager := isolatedNpm(t)
		t.Setenv("PREFIX", "")
		install := t.TempDir()
		writeNpmFixture(t, filepath.Join(install, "bin", "node"), "#!/bin/sh\n")
		if err := os.Chmod(filepath.Join(install, "bin", "node"), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", filepath.Join(install, "bin"))
		destdir := t.TempDir()
		t.Setenv("DESTDIR", destdir)
		resolved, err := filepath.EvalSymlinks(install)
		if err != nil {
			t.Fatal(err)
		}
		writeNpmFixture(t, filepath.Join(destdir, resolved, "etc", "npmrc"), "https-proxy=http://node:1\n")
		if got := projectProxy(t, manager); got != "http://node:1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("prefix setting moves the default", func(t *testing.T) {
		manager := isolatedNpm(t)
		other := t.TempDir()
		writeNpmFixture(t, filepath.Join(other, "etc", "npmrc"), "https-proxy=http://other:1\n")
		if got := projectProxy(t, manager, "--prefix", other); got != "http://other:1" {
			t.Fatalf("--prefix: %q", got)
		}
		writeNpmFixture(t, filepath.Join(os.Getenv("HOME"), ".npmrc"), "prefix="+other+"\n")
		if got := projectProxy(t, manager); got != "http://other:1" {
			t.Fatalf("user prefix: %q", got)
		}
	})
	// npm's default globalconfig is an accessor whose setter absorbs the first
	// layer, in CLI, env, project, user order, that assigns it.
	for _, test := range []struct {
		name                 string
		cli, env, proj, user bool
		want                 string
	}{
		{name: "only user", user: true, want: "http://user:1"},
		{name: "env demoted below user", env: true, user: true, want: "http://user:1"},
		{name: "cli demoted below env", cli: true, env: true, user: true, want: "http://env:1"},
		{name: "cli demoted below project", cli: true, proj: true, user: true, want: "http://proj:1"},
		{name: "only cli", cli: true, want: "http://cli:1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			dir := t.TempDir()
			var args []string
			if test.cli {
				args = []string{"--globalconfig", setter(t, dir, "cli")}
			}
			if test.env {
				t.Setenv("npm_config_globalconfig", setter(t, dir, "env"))
			}
			if test.proj {
				writeNpmFixture(t, ".npmrc", "globalconfig="+setter(t, dir, "proj")+"\n")
			}
			if test.user {
				writeNpmFixture(t, filepath.Join(os.Getenv("HOME"), ".npmrc"), "globalconfig="+setter(t, dir, "user")+"\n")
			}
			if got := projectProxy(t, manager, args...); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestSettingsExpandsPathKeys(t *testing.T) {
	manager := isolatedNpm(t)
	cwd, _ := os.Getwd()
	for value, want := range map[string]string{
		"~/ca.pem":   filepath.Join(os.Getenv("HOME"), "ca.pem"),
		"rel/ca.pem": filepath.Join(cwd, "rel", "ca.pem"),
		"/abs.pem":   "/abs.pem",
	} {
		writeNpmFixture(t, ".npmrc", "cafile="+value+"\n")
		result, err := manager.settings(nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.CAFile != want {
			t.Fatalf("cafile %q = %q, want %q", value, result.CAFile, want)
		}
	}
}
