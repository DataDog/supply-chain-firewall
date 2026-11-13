// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"net/url"
	"testing"
)

func TestNpmTrustURL(t *testing.T) {
	for _, test := range []struct {
		strictSSL bool
		target    *url.URL
		trusted   bool
	}{
		{false, &url.URL{Scheme: "https", Host: "registry.test"}, true},
		{false, &url.URL{Scheme: "http", Host: "registry.test"}, true},
		{false, &url.URL{Scheme: "ftp", Host: "registry.test"}, false},
		{false, nil, false},
		{true, &url.URL{Scheme: "https", Host: "registry.test"}, false},
	} {
		if got := npmTrustURL(test.strictSSL)(test.target); got != test.trusted {
			t.Errorf("npmTrustURL(%v)(%v) = %v, want %v", test.strictSSL, test.target, got, test.trusted)
		}
	}
}
