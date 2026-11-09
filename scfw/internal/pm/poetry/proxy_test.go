// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
)

func TestPoetryUpstreamProxy(t *testing.T) {
	for _, test := range []struct {
		name                string
		env                 map[string]string
		http, https, bypass string
		invalid             bool
	}{
		{name: "direct"},
		{name: "uppercase", env: map[string]string{"HTTP_PROXY": "http://user:secret@http.example:80", "HTTPS_PROXY": "https://user:secret@https.example:443", "NO_PROXY": "internal.example"}, http: "http://user:secret@http.example:80", https: "https://user:secret@https.example:443", bypass: "internal.example"},
		{name: "lowercase wins", env: map[string]string{"HTTP_PROXY": "http://wrong", "http_proxy": "http://right", "HTTPS_PROXY": "http://wrong", "https_proxy": "http://secure", "NO_PROXY": "wrong", "no_proxy": "right"}, http: "http://right", https: "http://secure", bypass: "right"},
		{name: "empty lowercase removes uppercase", env: map[string]string{"HTTP_PROXY": "http://wrong", "http_proxy": "", "HTTPS_PROXY": "http://wrong", "https_proxy": ""}},
		{name: "all fallback", env: map[string]string{"ALL_PROXY": "http://fallback", "https_proxy": "https://secure"}, http: "http://fallback", https: "https://secure"},
		{name: "all lowercase empty", env: map[string]string{"ALL_PROXY": "http://wrong", "all_proxy": ""}},
		{name: "empty lowercase bypass uses uppercase", env: map[string]string{"no_proxy": "", "NO_PROXY": "*"}, bypass: "*"},
		{name: "implicit scheme", env: map[string]string{"http_proxy": "user:secret@proxy.example:8080"}, http: "user:secret@proxy.example:8080"},
		{name: "CGI ignores uppercase HTTP", env: map[string]string{"REQUEST_METHOD": "GET", "HTTP_PROXY": "http://wrong", "HTTPS_PROXY": "http://secure"}, https: "http://secure"},
		{name: "CGI retains lowercase HTTP", env: map[string]string{"REQUEST_METHOD": "GET", "http_proxy": "http://right"}, http: "http://right"},
		{name: "invalid URL", env: map[string]string{"http_proxy": "http://user:secret%zz@proxy.example"}, invalid: true},
		{name: "unsupported scheme", env: map[string]string{"https_proxy": "socks5://user:secret@proxy.example"}, invalid: true},
		{name: "missing host", env: map[string]string{"http_proxy": "http://user:secret@"}, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "REQUEST_METHOD"} {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			for key, value := range test.env {
				t.Setenv(key, value)
			}
			config, err := (Poetry{version: minPoetryVersion}).UpstreamProxy([]string{"install"})
			if test.invalid {
				if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user") {
					t.Fatalf("unsafe/missing error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.HTTPProxy != test.http || config.HTTPSProxy != test.https || config.NoProxy != test.bypass {
				t.Fatalf("unexpected upstream settings: %#v", config)
			}
		})
	}
}

func TestPoetryProxyCommandPreservesArgumentsAndParent(t *testing.T) {
	t.Setenv("http_proxy", "http://original")
	t.Setenv("REQUESTS_CA_BUNDLE", "/original/requests.pem")
	t.Setenv("GIT_SSL_CAINFO", "/original/git.pem")
	before := os.Environ()
	args := []string{"--directory", "a project", "add", "--source", "private", "name @ https://user:secret@example.test/project.whl", "--", "--opaque"}
	wantArgs := slices.Clone(args)
	config := proxy.ClientConfig{URL: "http://127.0.0.1:1234", CACertificatePath: "/tmp/scfw/ca.pem"}
	spec, err := (Poetry{version: minPoetryVersion, executable: "/custom/poetry"}).ProxyCommand(context.Background(), args, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Executable != "/custom/poetry" || !slices.Equal(spec.Args, wantArgs) || !slices.Equal(args, wantArgs) {
		t.Fatalf("changed command: %#v", spec)
	}
	if !slices.Equal(before, os.Environ()) {
		t.Fatal("parent environment changed")
	}
	for key, value := range spec.EnvOverrides {
		want := config.URL
		switch key {
		case "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "SSL_CERT_FILE":
			want = config.CACertificatePath
		case "no_proxy", "NO_PROXY":
			want = ""
		case "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY":
		default:
			t.Fatalf("unrelated override: %s", key)
		}
		if value != want {
			t.Errorf("%s=%q, want %q", key, value, want)
		}
	}
	if len(spec.EnvOverrides) != 11 {
		t.Fatal("missing routing or trust overrides")
	}
	spec.Args[0] = "changed"
	if !slices.Equal(args, wantArgs) {
		t.Fatal("command spec aliases input")
	}
}

func TestPoetryProxyOptionsTrust(t *testing.T) {
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Setenv(key, "")
	}
	server, err := proxy.Start(context.Background(), proxy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	ca := server.ClientConfig().CACertificatePath
	for _, key := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		t.Run(key, func(t *testing.T) {
			path := ca
			if key == "GIT_SSL_CAPATH" || key == "SSL_CERT_DIR" {
				path = filepath.Dir(ca)
			}
			t.Setenv(key, path)
			options, err := (Poetry{version: minPoetryVersion}).ProxyOptions(nil)
			if err != nil || options.UpstreamTLS == nil || options.UpstreamTLS.RootCAs == nil {
				t.Fatalf("trust not loaded: %v", err)
			}
			t.Setenv(key, "/missing/secret.pem")
			if _, err := (Poetry{version: minPoetryVersion}).ProxyOptions(nil); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe/missing error: %v", err)
			}
		})
	}
	t.Setenv("REQUESTS_CA_BUNDLE", ca)
	t.Setenv("CURL_CA_BUNDLE", "/ignored")
	if _, err := (Poetry{version: minPoetryVersion}).ProxyOptions(nil); err != nil {
		t.Fatal(err)
	}
}

func TestPoetryClassifierSources(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	nested := filepath.Join(project, "nested")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := readPoetryFixture("proxy-sources.toml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(project, "pyproject.toml")
	if err := os.WriteFile(manifest, data, 0400); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-C", nested, "install"},
		{"--directory=" + root, "--project", "project", "lock"},
		{"-C" + root, "-Pproject", "add", "name"},
		{"--project=" + project, "update"},
	} {
		options, err := (Poetry{version: minPoetryVersion}).PyPIClassifierOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"https://user:secret@index.example/python-packages/", "https://index.example/explicit/"}
		if !reflect.DeepEqual(options.SimpleIndexURLs, want) {
			t.Fatalf("sources=%v, want %v", options.SimpleIndexURLs, want)
		}
	}
	after, err := os.ReadFile(manifest)
	if err != nil || !slices.Equal(data, after) {
		t.Fatal("source configuration changed")
	}
}

func TestPoetryOutboundProxyRouting(t *testing.T) {
	for _, test := range []struct{ target, bypass, want string }{
		{"http://public.example", "", "http://user:secret@http.example"},
		{"https://public.example", "", "https://https.example"},
		{"http://127.0.0.1:1234", "", "http://user:secret@http.example"},
		{"http://127.0.0.1:1234", "127.0.0.1:1234", "http://user:secret@http.example"},
		{"http://[::ffff:10.0.0.1]", "10.0.0.0/8", "http://user:secret@http.example"},
		{"https://internal.example:8443", "INTERNAL.example:8443", "https://https.example"},
		{"http://localhost:1234", "", "http://user:secret@http.example"},
		{"https://public.example", "*", ""},
		{"https://sub.internal.example", ".internal.example", ""},
		{"https://internal.example:8443", "internal.example:8443", ""},
		{"https://internal.example:8443", "internal.example:443", "https://https.example"},
		{"http://10.1.2.3", "10.0.0.0/8", ""},
		{"http://notinternal.example", "internal.example", "http://user:secret@http.example"},
		{"https://INTERNAL.example", "internal.EXAMPLE", ""},
	} {
		t.Run(test.target+"/"+test.bypass, func(t *testing.T) {
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			settings := httpproxy.Config{HTTPProxy: "http://user:secret@http.example", HTTPSProxy: "https://https.example", NoProxy: test.bypass}
			got, err := poetryProxyForURL(settings)(target)
			if err != nil {
				t.Fatal(err)
			}
			if test.want == "" {
				if got != nil {
					t.Fatal("bypassed target has upstream proxy")
				}
			} else if got == nil || got.String() != test.want {
				t.Fatalf("wrong upstream: %v", got)
			}
			got, err = poetryProxyForURL(httpproxy.Config{})(target)
			if err != nil || got != nil {
				t.Fatalf("absent proxies must connect directly: %v / %v", got, err)
			}
		})
	}
}

func TestPoetryProxyRejectsUnsupportedVersions(t *testing.T) {
	for _, manager := range []Poetry{
		{version: pm.Version{Major: 1, Minor: 7}},
		{version: pm.Version{Major: 1, Minor: 8, Patch: 5}},
		{versionErr: errors.New("could not determine version")},
	} {
		if _, err := manager.ProxyOptions([]string{"install"}); !errors.Is(err, pm.ErrUnsupportedVersion) {
			t.Fatalf("proxy setup accepted unsupported Poetry: %v", err)
		}
		directory := t.TempDir()
		config := proxy.ClientConfig{URL: "http://127.0.0.1:1234", CACertificatePath: filepath.Join(directory, "ca.pem")}
		if _, err := manager.ProxyCommand(context.Background(), []string{"install"}, config); !errors.Is(err, pm.ErrUnsupportedVersion) {
			t.Fatalf("child setup accepted unsupported Poetry: %v", err)
		}
		if _, err := os.Stat(filepath.Join(directory, "gitconfig")); !os.IsNotExist(err) {
			t.Fatal("unsupported Poetry created an invocation Git snapshot")
		}
	}
}
