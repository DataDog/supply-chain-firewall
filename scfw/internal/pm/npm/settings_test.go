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
