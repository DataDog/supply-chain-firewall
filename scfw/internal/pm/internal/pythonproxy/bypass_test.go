// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pythonproxy

import "testing"

func TestValidateHTTPSBypass(t *testing.T) {
	for _, test := range []struct {
		name, pattern string
		loose, reject bool
	}{
		{"default", "files.example:443", false, true},
		{"unicode-prepared-host", "éxample.test:443", false, false},
		{"legacy-unicode-prepared-host", "éxample.test:443", true, false},
		{"suffix", ".example:443", false, true},
		{"spaces", "localhost, files .example :443", false, true},
		{"legacy-port-only", ":443", true, true},
		{"modern-port-only-does-not-match", ":443", false, false},
		{"bare-ipv6", "2001:db8::1:443", false, true},
		{"legacy-ipv6-suffix", "db8:1:443", true, true},
		{"modern-ipv6-suffix", "db8:1:443", false, false},
		{"legacy-ipv6-colon-suffix", ":1:443", true, true},
		{"modern-ipv6-colon-suffix", ":1:443", false, false},
		{"ipv6-address-ending-in-443", "2001:db8::443", false, false},
		{"ipv6-address-ending-in-443-legacy", "2001:db8::443", true, false},
		{"redundant-host-port", "files.example,files.example:443", false, false},
		{"redundant-suffix-port", ".example,files.example:443", false, false},
		{"redundant-ipv6-port", "2001:db8::1,2001:db8::1:443", false, false},
		{"noncovering-host", "files.example,other.example:443", false, true},
		{"noncovering-narrow-host", "files.example,.example:443", false, true},
		{"legacy-redundant-suffix", "example,filesexample:443", true, false},
		{"modern-distinct-suffix", "example,filesexample:443", false, true},
		{"ipv4-port-does-not-match", "127.0.0.1:443", false, false},
		{"bracketed-ipv6-does-not-match", "[2001:db8::1]:443", false, false},
		{"uppercase-port-does-not-match", "FILES.example:443", false, false},
		{"wildcard-port-does-not-match", "*:443", false, false},
		{"nondefault", "files.example:8443", false, false},
		{"http-default", "files.example:80", false, false},
		{"domain", "files.example", false, false},
		{"wildcard", "*", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateHTTPSBypass(test.pattern, test.pattern, test.loose); (err != nil) != test.reject {
				t.Fatalf("reject=%v, error=%v", test.reject, err)
			}
		})
	}
}

func TestValidateHTTPSBypassIndependentLists(t *testing.T) {
	for _, test := range []struct {
		requests, urllib string
		reject           bool
	}{
		{"files.example:443", "files.example", false},
		{"files.example:443", "*", false},
		{"files.example:443", "other.example", true},
		{"FILES.EXAMPLE,files.example:443", "other.example", true},
		{"FILES.EXAMPLE,files.example:443", "FILES.EXAMPLE", false},
		{"2001:db8::1:443", "2001:db8:", false},
	} {
		if err := ValidateHTTPSBypass(test.requests, test.urllib, false); (err != nil) != test.reject {
			t.Fatalf("Requests=%q urllib=%q reject=%v: %v", test.requests, test.urllib, test.reject, err)
		}
	}
}
