// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"slices"
	"testing"
)

func TestParseNpmOptions(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []npmOption
	}{
		{"space form", []string{"install", "x", "--https-proxy", "http://a:1"}, []npmOption{{"https-proxy", "http://a:1"}}},
		{"equals form", []string{"--proxy=http://p:2", "install"}, []npmOption{{"proxy", "http://p:2"}}},
		{"explicit empty value", []string{"install", "--https-proxy="}, []npmOption{{"https-proxy", ""}}},
		{"prefix shorthand", []string{"-C", "dir", "install"}, []npmOption{{"prefix", "dir"}}},
		{"global shorthand", []string{"-g", "install"}, []npmOption{{"global", "true"}}},
		{"global flag", []string{"install", "--global"}, []npmOption{{"global", "true"}}},
		{"location", []string{"--location", "global", "install"}, []npmOption{{"location", "global"}}},
		{"strict-ssl value", []string{"--strict-ssl", "false", "install"}, []npmOption{{"strict-ssl", "false"}}},
		{"strict-ssl equals", []string{"--strict-ssl=false"}, []npmOption{{"strict-ssl", "false"}}},
		{"strict-ssl negated", []string{"--no-strict-ssl"}, []npmOption{{"strict-ssl", "false"}}},
		{"strict-ssl bare", []string{"--strict-ssl", "install"}, []npmOption{{"strict-ssl", "true"}}},
		{"scoped registry", []string{"--@lab:registry=https://r/"}, []npmOption{{"@lab:registry", "https://r/"}}},
		{"value missing at end", []string{"install", "--https-proxy"}, nil},
		{"after separator", []string{"install", "--", "--https-proxy=x"}, nil},
		{"abbreviation", []string{"--https-prox=x"}, nil},
		{"unrelated options", []string{"--loglevel=warn", "--save-dev", "install"}, nil},
		{"last occurrence kept in order", []string{"--https-proxy=http://a:1", "--https-proxy=http://b:2"},
			[]npmOption{{"https-proxy", "http://a:1"}, {"https-proxy", "http://b:2"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := parseNpmOptions(test.args); !slices.Equal(got, test.want) {
				t.Fatalf("parseNpmOptions(%q) = %v, want %v", test.args, got, test.want)
			}
		})
	}
}
