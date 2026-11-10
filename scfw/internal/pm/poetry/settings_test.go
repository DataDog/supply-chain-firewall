// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
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
