// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"maps"
	"net/url"
	"testing"
)

func TestBypasses(t *testing.T) {
	for _, test := range []struct {
		host, noProxy string
		bypass        bool
	}{
		{"registry.lab.test", "lab.test", true},
		{"registry.lab.test", ".lab.test", true},
		{"notlab.test", "lab.test", false},
		{"registry.lab.test", "*", false},
		{"registry.lab.test", "registry.lab.test:443", false},
		{"registry.lab.test", "REGISTRY.LAB.TEST", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"a.test", " a.test , b.test ", true},
		{"b.test", " a.test , b.test ", true},
		{"registry.lab.test", "", false},
	} {
		target := &url.URL{Scheme: "https", Host: test.host + ":443"}
		if got := Bypasses(target, test.noProxy); got != test.bypass {
			t.Errorf("Bypasses(%q, %q) = %v, want %v", test.host, test.noProxy, got, test.bypass)
		}
	}
}

func TestOverrideVariants(t *testing.T) {
	environ := []string{"Https_Proxy=x", "NPM_CONFIG-PROXY=y", "OTHER=z"}
	got := OverrideVariants(environ, map[string]string{"https_proxy": "P", "npm_config_proxy": "P"})
	want := map[string]string{"https_proxy": "P", "npm_config_proxy": "P", "Https_Proxy": "P", "NPM_CONFIG-PROXY": "P"}
	if !maps.Equal(got, want) {
		t.Fatalf("OverrideVariants = %v, want %v", got, want)
	}
}
