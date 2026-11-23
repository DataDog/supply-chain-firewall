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
		{"suffix", ".example:443", false, true},
		{"spaces", "localhost, files .example :443", false, true},
		{"legacy-port-only", ":443", true, true},
		{"modern-port-only-does-not-match", ":443", false, false},
		{"bare-ipv6", "2001:db8::1:443", false, true},
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
			if err := ValidateHTTPSBypass(test.pattern, test.loose); (err != nil) != test.reject {
				t.Fatalf("reject=%v, error=%v", test.reject, err)
			}
		})
	}
}
