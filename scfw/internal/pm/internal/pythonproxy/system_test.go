// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pythonproxy

import (
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSystemProxyVariants(t *testing.T) {
	data, err := os.ReadFile("testdata/system-proxy.txt")
	if err != nil {
		t.Fatal(err)
	}
	fixture := string(data)
	for _, test := range []struct {
		name, before, after string
		want                map[string]string
	}{
		{"disabled", "HTTPEnable : 1", "HTTPEnable : 0", map[string]string{"https": "http://secure-proxy.example:8443"}},
		{"no port", "  HTTPPort : 8080\n", "", map[string]string{"http": "http://proxy.example", "https": "http://secure-proxy.example:8443"}},
		{"IPv6", "HTTPProxy : proxy.example", "HTTPProxy : 2001:db8::1", map[string]string{"http": "http://[2001:db8::1]:8080", "https": "http://secure-proxy.example:8443"}},
		{"credentials", "HTTPProxy : proxy.example", "HTTPProxy : user:secret@proxy.example", map[string]string{"http": "http://user:secret@proxy.example:8080", "https": "http://secure-proxy.example:8443"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings, err := ParseSystem(strings.ReplaceAll(fixture, test.before, test.after))
			if err != nil || !reflect.DeepEqual(settings.Proxies, test.want) {
				t.Fatalf("settings=%+v error=%v", settings, err)
			}
		})
	}
	for _, output := range []string{"<dictionary> {\n}\n", "No proxy configuration available\n"} {
		settings, err := ParseSystem(output)
		if err != nil || len(settings.Proxies) != 0 {
			t.Fatalf("empty settings=%+v error=%v", settings, err)
		}
	}
	for _, output := range []string{"credential-secret", strings.TrimSuffix(fixture, "}\n")} {
		if _, err := ParseSystem(output); err == nil || strings.Contains(err.Error(), "credential-secret") {
			t.Fatalf("unsafe parsing error: %v", err)
		}
	}
	settings := Settings{Exceptions: []string{"10/33", "10/bad", "10/-1"}}
	target, _ := url.Parse("https://10.1.2.3")
	if settings.Bypasses(target) {
		t.Fatal("invalid network masks bypassed the proxy")
	}
}
