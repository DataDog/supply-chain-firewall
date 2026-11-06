// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"net/url"
	"os"
	"testing"
)

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
