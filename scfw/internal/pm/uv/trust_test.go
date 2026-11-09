// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestTrustedHosts(t *testing.T) {
	content, err := os.ReadFile("testdata/trust.toml")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]map[string]any
	if err := toml.Unmarshal(content, &cases); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UV_INSECURE_HOST", "environment.example")
	for _, test := range []struct {
		name, target string
		want         bool
	}{
		{"mixed", "https://string.example", true}, {"mixed", "https://string.example:8443", true},
		{"mixed", "https://sub.string.example", false}, {"mixed", "https://other.example", false},
		{"mixed", "https://table.example:8443", true}, {"mixed", "https://table.example:8444", false},
		{"mixed", "http://table.example:8443", false}, {"mixed", "https://table.example", false},
		{"mixed", "https://[::1]:9443", true}, {"mixed", "https://[::1]:9444", false},
		{"mixed", "https://environment.example", true}, {"wildcard", "https://other.example", true},
		{"literal-star", "https://other.example", false}, {"default-port", "https://port.example:443", false},
	} {
		t.Run(test.name+"/"+test.target, func(t *testing.T) {
			match, err := trustURL(cases[test.name], commandOptions{})
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(test.target)
			if got := match(target); got != test.want {
				t.Fatalf("trust=%v, want %v", got, test.want)
			}
			if match(nil) {
				t.Fatal("nil URL was trusted")
			}
		})
	}
	for _, name := range []string{"bad-port", "bad-type", "missing-host", "bad-string", "bad-list"} {
		if _, err := trustURL(cases[name], commandOptions{}); err == nil || strings.Contains(err.Error(), "credential-secret") {
			t.Fatalf("%s: unsafe or missing error: %v", name, err)
		}
	}
	for _, args := range [][]string{{"pip", "install", "--trusted-host", "cli.example other.example"}, {"pip", "install", "--allow-insecure-host="}} {
		match, err := trustURL(cases["mixed"], parseOptions(args))
		if err != nil {
			t.Fatal(err)
		}
		for target, want := range map[string]bool{"https://string.example": true, "https://environment.example": false, "https://cli.example": len(args) == 4, "https://other.example": len(args) == 4} {
			parsed, _ := url.Parse(target)
			if match(parsed) != want {
				t.Fatalf("%v: trust for %s != %v", args, target, want)
			}
		}
	}
}
