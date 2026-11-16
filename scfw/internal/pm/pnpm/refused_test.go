// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Client certificates cannot pass through the intercepting proxy, and a local
// address or pnpr server would route around it.
func TestRefusedSettings(t *testing.T) {
	const value = "/secret/client.pem"
	npmrc := func(key string) func(*testing.T, pnpmLayout) {
		return func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/setting.npmrc.tmpl", key, value)
		}
	}
	workspaceYAML := func(key string) func(*testing.T, pnpmLayout) {
		return func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, "pnpm-workspace.yaml"), "workspace-yaml/setting.yaml.tmpl", key, value)
		}
	}
	for _, test := range []struct {
		name, setting string
		majors        []int
		command       string
		prepare       func(*testing.T, pnpmLayout)
	}{
		{"npmrc cert", "cert", []int{10, 11}, "add x", npmrc("cert")},
		{"npmrc key", "key", []int{10, 11}, "add x", npmrc("key")},
		{"npmrc registry certfile", "//r.test/:certfile", []int{10, 11, 12}, "add x", npmrc("//r.test/:certfile")},
		{"npmrc registry keyfile", "//r.test/:keyfile", []int{10, 11, 12}, "add x", npmrc("//r.test/:keyfile")},
		{"npmrc registry cert", "//r.test/:cert", []int{10, 11, 12}, "add x", npmrc("//r.test/:cert")},
		{"npmrc local-address", "local-address", []int{10, 11, 12}, "add x", npmrc("local-address")},
		{"workspace localAddress", "local-address", []int{10, 11, 12}, "add x", workspaceYAML("localAddress")},
		{"workspace pnprServer", "pnpr-server", []int{11, 12}, "add x", workspaceYAML("pnprServer")},
		{"npm_config_local_address", "local-address", []int{10}, "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("npm_config_local_address", value)
		}},
		{"pnpm_config_local_address", "local-address", []int{11, 12}, "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("pnpm_config_local_address", value)
		}},
		{"command-line cert", "cert", []int{10, 11, 12}, "--config.cert=" + value + " add x", func(*testing.T, pnpmLayout) {}},
	} {
		for _, major := range test.majors {
			t.Run(fmt.Sprintf("%s/%d", test.name, major), func(t *testing.T) {
				layout := newPnpmWorkspace(t)
				test.prepare(t, layout)
				_, err := fakePnpm(t, map[int]string{10: "10.34.9", 11: "11.28.9", 12: "12.18.0"}[major]).UpstreamProxy(strings.Fields(test.command))
				if err == nil || err.Error() != "pnpm "+test.setting+" is not supported through SCFW" {
					t.Fatalf("error = %v", err)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Fatal("the error must not echo the setting's value")
				}
			})
		}
	}
}
