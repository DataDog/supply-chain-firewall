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

var yamlVersions = map[int]string{11: "11.28.9", 12: "12.18.0"}

func TestYAMLUpstreamPrecedence(t *testing.T) {
	workspaceYAML := func(t *testing.T, l pnpmLayout) {
		writePnpmFixture(t, filepath.Join(l.workspace, "pnpm-workspace.yaml"), "workspace-yaml/https-proxy.yaml.tmpl", "http://yaml:1")
	}
	configYAML := func(t *testing.T, l pnpmLayout) {
		writePnpmFixture(t, filepath.Join(l.configDir(), "config.yaml"), "config-yaml/https-proxy.yaml.tmpl", "http://global-yaml:1")
	}
	npmrc := func(t *testing.T, l pnpmLayout) {
		writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://npmrc:1")
	}
	for _, test := range []struct {
		name    string
		majors  []int
		command string
		prepare func(t *testing.T, layout pnpmLayout)
		https   string
	}{
		{"cli beats env", []int{11, 12}, "--config.https-proxy=http://cli:1 add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("pnpm_config_https_proxy", "http://env:1")
		}, "http://cli:1"},
		{"env beats workspace yaml", []int{11, 12}, "add x", func(t *testing.T, l pnpmLayout) {
			workspaceYAML(t, l)
			t.Setenv("pnpm_config_https_proxy", "http://env:1")
		}, "http://env:1"},
		{"workspace yaml beats config.yaml", []int{11, 12}, "add x", func(t *testing.T, l pnpmLayout) {
			workspaceYAML(t, l)
			configYAML(t, l)
		}, "http://yaml:1"},
		{"config.yaml beats npmrc", []int{11, 12}, "add x", func(t *testing.T, l pnpmLayout) {
			configYAML(t, l)
			npmrc(t, l)
		}, "http://global-yaml:1"},
		{"workspace npmrc", []int{11, 12}, "add x", npmrc, "http://npmrc:1"},
		{"mixed-case prefix is ignored", []int{11}, "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("Pnpm_Config_Https_Proxy", "http://mixed:1")
		}, ""},
		{"npm_config is ignored", []int{11, 12}, "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("npm_config_https_proxy", "http://npm:1")
		}, ""},
		{"uppercase PNPM_CONFIG", []int{11, 12}, "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("PNPM_CONFIG_HTTPS_PROXY", "http://upper-env:1")
		}, "http://upper-env:1"},
	} {
		for _, major := range test.majors {
			t.Run(fmt.Sprintf("%s/%d", test.name, major), func(t *testing.T) {
				layout := newPnpmWorkspace(t)
				test.prepare(t, layout)
				config, err := fakePnpm(t, yamlVersions[major]).UpstreamProxy(strings.Fields(test.command))
				if err != nil || config.HTTPSProxy != test.https {
					t.Fatalf("HTTPSProxy = %q (error %v), want %q", config.HTTPSProxy, err, test.https)
				}
			})
		}
	}
}

func TestYAMLStandardProxyVariables(t *testing.T) {
	for major, want := range map[int]string{11: "http://lower:1", 12: "http://upper:1"} {
		newPnpmWorkspace(t)
		t.Setenv("https_proxy", "http://lower:1")
		t.Setenv("HTTPS_PROXY", "http://upper:1")
		config, err := fakePnpm(t, yamlVersions[major]).UpstreamProxy([]string{"add", "x"})
		if err != nil || config.HTTPSProxy != want {
			t.Errorf("pnpm %d: HTTPSProxy = %q (error %v), want %q", major, config.HTTPSProxy, err, want)
		}
	}
}

func TestYAMLNoProxy(t *testing.T) {
	for _, major := range []int{11, 12} {
		layout := newPnpmWorkspace(t)
		writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/noproxy.npmrc")
		config, err := fakePnpm(t, yamlVersions[major]).UpstreamProxy([]string{"add", "x"})
		if major == 11 && (err != nil || config.NoProxy != "") {
			t.Errorf("pnpm 11 must not read noproxy from .npmrc: %q (error %v)", config.NoProxy, err)
		}
		writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/no-proxy.npmrc")
		if config, err = fakePnpm(t, yamlVersions[major]).UpstreamProxy([]string{"add", "x"}); err != nil || config.NoProxy != "c.test" {
			t.Errorf("pnpm %d: .npmrc no-proxy = %q (error %v)", major, config.NoProxy, err)
		}
		writePnpmFixture(t, filepath.Join(layout.configDir(), "config.yaml"), "config-yaml/no-proxy.yaml")
		if config, err = fakePnpm(t, yamlVersions[major]).UpstreamProxy([]string{"add", "x"}); err != nil || config.NoProxy != "d.test" {
			t.Errorf("pnpm %d: config.yaml noProxy = %q (error %v)", major, config.NoProxy, err)
		}
	}
}

func TestYAMLSettingsFromWorkspaceRoot(t *testing.T) {
	for _, major := range []int{11, 12} {
		layout := newPnpmWorkspace(t)
		member := filepath.Join(layout.workspace, "packages", "a")
		writePnpmFixture(t, filepath.Join(member, "package.json"), "manifest/member.json")
		writePnpmFixture(t, filepath.Join(layout.workspace, "pnpm-workspace.yaml"), "workspace-yaml/https-proxy.yaml.tmpl", "http://workspace:1")
		t.Chdir(layout.workspace)
		config, err := fakePnpm(t, yamlVersions[major]).UpstreamProxy([]string{"-C", "packages/a", "add", "x"})
		if err != nil || config.HTTPSProxy != "http://workspace:1" {
			t.Errorf("pnpm %d: HTTPSProxy = %q (error %v), want the workspace root's proxy", major, config.HTTPSProxy, err)
		}
	}
}

func TestYAMLUpstreamRejectsInvalidURLWithoutCredentials(t *testing.T) {
	for _, major := range []int{11, 12} {
		for _, value := range []string{"socks5://user:secret@h:1", "http://user:secret@[bad"} {
			layout := newPnpmWorkspace(t)
			writePnpmFixture(t, filepath.Join(layout.workspace, "pnpm-workspace.yaml"), "workspace-yaml/https-proxy.yaml.tmpl", value)
			_, err := fakePnpm(t, yamlVersions[major]).UpstreamProxy([]string{"add", "x"})
			if err == nil || err.Error() != "unsupported or invalid pnpm upstream proxy URL" || strings.Contains(err.Error(), "secret") {
				t.Errorf("pnpm %d %s: error = %v", major, value, err)
			}
		}
	}
}
