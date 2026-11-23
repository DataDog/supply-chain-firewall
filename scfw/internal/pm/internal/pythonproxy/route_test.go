// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pythonproxy

import (
	"errors"
	"net/url"
	"testing"
)

func TestValidateHTTPSRoute(t *testing.T) {
	for _, test := range []struct {
		name, target, implicit, explicit string
		reject                           bool
	}{
		{"implicit-default", "https://files.example/a.whl", "http://gateway.example", "", true},
		{"explicit-default", "https://files.example:443/a.whl", "http://gateway.example", "", true},
		{"same-route", "https://files.example/a.whl", "http://gateway.example", "http://gateway.example", false},
		{"HTTP-proxy-default-port", "https://files.example/a.whl", "http://gateway.example", "http://GATEWAY.example:80", false},
		{"HTTPS-proxy-default-port", "https://files.example/a.whl", "https://gateway.example", "https://gateway.example:443", false},
		{"different-auth", "https://files.example/a.whl", "http://one@gateway.example", "http://two@gateway.example", true},
		{"nondefault", "https://files.example:8443/a.whl", "http://gateway.example", "", false},
		{"HTTP", "http://files.example/a.whl", "http://gateway.example", "", false},
		{"IPv6", "https://[2001:db8::1]/a.whl", "http://gateway.example", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, _ := url.Parse(test.target)
			route := func(u *url.URL) (*url.URL, error) {
				if u.Hostname() != target.Hostname() || u.Path != target.Path {
					t.Fatalf("destination changed: %s", u)
				}
				value := test.implicit
				if u.Port() == "443" {
					value = test.explicit
				}
				if value == "" {
					return nil, nil
				}
				return url.Parse(value)
			}
			err := ValidateHTTPSRoute(target, route)
			if errors.Is(err, ErrAmbiguousHTTPSBypass) != test.reject {
				t.Fatalf("reject=%v: %v", test.reject, err)
			}
			if target.String() != test.target {
				t.Fatalf("mutated target: %s", target)
			}
		})
	}
}

func TestValidateHTTPSRouteRedactsSelectionErrors(t *testing.T) {
	target, _ := url.Parse("https://files.example/project.whl")
	err := ValidateHTTPSRoute(target, func(*url.URL) (*url.URL, error) { return nil, errors.New("private credentials") })
	if err == nil || err.Error() != "could not resolve Python proxy route" {
		t.Fatalf("unsafe route error: %v", err)
	}
}
