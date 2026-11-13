// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestParseNpmrc(t *testing.T) {
	env := map[string]string{"CORP": "http://env:1", "SCOPE": "lab"}
	for _, test := range []struct {
		fixture string
		want    Config
		absent  []string
	}{
		// Quotes survive when an inline comment follows them, as in npm.
		{"crlf-bom.npmrc", Config{"https-proxy": {`"http://q:1"`}, "proxy": {"http://crlf:2"}}, nil},
		{"cr-only.npmrc", Config{"https-proxy": {"http://cr:1"}, "proxy": {"http://cr2:2"}}, nil},
		{"syntax.npmrc", Config{
			"https-proxy": {"http://sp:1"}, "proxy": {"http://q:1/;x"}, "noproxy": {"http://c:1"},
			"registry": {"http://h:1/"}, "cafile": {"/single/quoted.pem"}, "ca": {"a\nb\"c"},
			"globalconfig": {"a;b"}, "userconfig": {`"http://u:1`}, "strict-ssl": {"true"}, "prefix": {"last"},
		}, nil},
		{"expansion.npmrc", Config{
			"https-proxy": {"http://env:1"}, "proxy": {"${UNSET}"}, "noproxy": {"xy"},
			"registry": {"http://r/${CORP}"}, "@lab:registry": {"http://k:1/"},
		}, nil},
		{"sections.npmrc", Config{"https-proxy": {"http://top:1"}}, []string{"proxy"}},
		{"arrays.npmrc", Config{"noproxy": {"a.test", "b.test"}, "ca": {"x", "y"}}, nil},
		{"credentials.npmrc", Config{}, []string{"https-proxy", "_authToken"}},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "npmrc", test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			got := ParseNpmrc(data, env)
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

func TestLoadNpmrcMissingAndUnreadable(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{
		"empty path": "",
		"missing":    filepath.Join(dir, "missing.npmrc"),
		"not a dir":  filepath.Join(dir, "file", ".npmrc"),
	} {
		if name == "not a dir" {
			if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		config, err := LoadNpmrc(path, nil)
		if err != nil || len(config) != 0 {
			t.Errorf("%s: config=%v err=%v, want empty", name, config, err)
		}
	}
	for name, prepare := range map[string]func(path string) error{
		"fifo":      func(path string) error { return syscall.Mkfifo(path, 0600) },
		"oversized": func(path string) error { return os.WriteFile(path, []byte(strings.Repeat("#", 8<<20+1)), 0600) },
	} {
		path := filepath.Join(dir, name)
		if err := prepare(path); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadNpmrc(path, nil); err == nil || err.Error() != "could not read npm configuration" {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestEnvironmentConfig(t *testing.T) {
	got := EnvironmentConfig([]string{
		"NPM_CONFIG_HTTPS_PROXY=http://a:1", "npm_config_https-proxy=http://b:1",
		"npm_config_proxy=", "npm_config_//host/:_authToken=secret", "HOME=/home",
	})
	if !slices.Equal(got["https-proxy"], []string{"http://b:1"}) || len(got) != 1 {
		t.Fatalf("environment config = %v", got)
	}
}
