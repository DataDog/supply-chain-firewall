// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"errors"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
)

func TestSystemProxySettingsAndRouting(t *testing.T) {
	settings, err := parseSystemProxies(readPipFixture(t, "config/system-proxy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"http": "http://proxy.example:8080", "https": "http://secure-proxy.example:8443"}
	if !reflect.DeepEqual(settings.proxies, want) {
		t.Fatalf("native proxies: %v", settings.proxies)
	}
	for _, fallback := range []string{"", "http://explicit.example"} {
		route := pipProxyForURL(pipDiscoveryResult{
			HTTP: settings.proxies["http"], HTTPS: settings.proxies["https"],
			FallbackHTTP: fallback, FallbackHTTPS: fallback, SystemProxyBypass: settings.bypasses,
		})
		for _, test := range []struct {
			url    string
			bypass bool
		}{
			{"http://registry.example/project.whl", false},
			{"https://registry.example/project.whl", false},
			{"https://printer/project.whl", true},
			{"https://registry.local:8443/project.whl", true},
			{"https://notlocal.example/project.whl", false},
			{"https://169.254.12.34/project.whl", true},
			{"https://169.253.12.34/project.whl", false},
			{"https://10.1.2.3/project.whl", true},
			{"https://10.10.2.3/project.whl", false},
			{"https://192.0.2.42/project.whl", true},
			{"https://192.0.2.43/project.whl", false},
			{"https://private.example/project.whl", true},
			{"https://other.private.example/project.whl", false},
			{"https://service1.example/project.whl", true},
			{"https://service12.example/project.whl", false},
			{"https://api1.internal/project.whl", true},
			{"https://api0.internal/project.whl", false},
		} {
			target, err := url.Parse(test.url)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := route(target)
			got := ""
			if selected != nil {
				got = selected.String()
			}
			want := settings.proxies[target.Scheme]
			if test.bypass {
				want = fallback
			}
			if err != nil || got != want {
				t.Fatalf("%s fallback=%q: proxy=%q want=%q error=%v", test.url, fallback, got, want, err)
			}
		}
	}
}

func TestEnvironmentProxiesSuppressSystemDiscovery(t *testing.T) {
	goDiscoveryPip(t)
	if err := os.Unsetenv("scfw_test_proxy"); err != nil {
		t.Fatal(err)
	}
	native, err := parseSystemProxies(readPipFixture(t, "config/system-proxy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		key, value string
		system     bool
	}{
		{"http_proxy", "", true},
		{"http_proxy", "http://environment.example", false},
		{"HTTPS_PROXY", "http://environment.example", false},
		{"NO_PROXY", "private.example", false},
		{"PIP_PROXY", "http://explicit.example", false},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			called := false
			settings, err := pipProxies(func() (systemProxySettings, error) {
				called = true
				return native, nil
			})
			if err != nil || called != test.system {
				t.Fatalf("system discovery called=%v want=%v error=%v", called, test.system, err)
			}
			if test.system && !reflect.DeepEqual(settings.proxies, native.proxies) {
				t.Fatalf("system proxies lost: %v", settings.proxies)
			}
			if !test.system && !reflect.DeepEqual(settings.proxies, pipEnvironmentProxies()) {
				t.Fatalf("environment proxies changed: %v", settings.proxies)
			}
		})
	}
	failure := errors.New("system proxy unavailable")
	if _, err := pipProxies(func() (systemProxySettings, error) { return systemProxySettings{}, failure }); !errors.Is(err, failure) {
		t.Fatalf("system discovery failure silently fell back to direct routing: %v", err)
	}
}

func parseSystemProxies(value string) (systemProxySettings, error) {
	settings, err := pythonproxy.ParseSystem(value)
	return fromNativeProxy(settings), err
}
