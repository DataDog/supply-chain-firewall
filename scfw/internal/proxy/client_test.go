// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"strings"
	"testing"
)

func TestUpstreamProxyURLPreservesCredentialsAndRedactsErrors(t *testing.T) {
	for _, value := range []string{"proxy.example:8080", "user:secret@proxy.example:8080", "https://user:secret@proxy.example:8080"} {
		address, err := ParseUpstreamProxyURL(value)
		if err != nil || address.Host != "proxy.example:8080" {
			t.Fatalf("proxy URL: %v/%v", address, err)
		}
		if strings.Contains(value, "secret") {
			password, _ := address.User.Password()
			if password != "secret" {
				t.Fatal("proxy credentials were lost")
			}
		}
	}
	for _, value := range []string{"http://user:secret%zz@proxy.example", "http://user:secret@", "socks5://user:secret@proxy.example"} {
		if _, err := ParseUpstreamProxyURL(value); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe or missing proxy validation error: %v", err)
		}
	}
	if address, err := ParseUpstreamProxyURL(""); address != nil || err != nil {
		t.Fatal("empty proxy must select a direct connection")
	}
}
