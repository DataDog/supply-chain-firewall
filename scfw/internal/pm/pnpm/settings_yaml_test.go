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

// The user .npmrc can be chosen on the command line; SCFW must read the same
// file pnpm reads, or it loses that file's proxy and CA.
func TestCommandLineUserconfig(t *testing.T) {
	for _, test := range []struct {
		major   int
		command func(company, other string) []string
		env     func(company string) [2]string
	}{
		{major: 10, command: func(c, _ string) []string { return []string{"--userconfig=" + c, "add", "x"} }},
		{major: 10, command: func(c, _ string) []string { return []string{"add", "x", "--userconfig", c} }},
		{major: 10, command: func(c, _ string) []string { return []string{"--config.userconfig=" + c, "add", "x"} }},
		{major: 11, command: func(c, _ string) []string { return []string{"--userconfig=" + c, "add", "x"} }},
		{major: 11, command: func(c, _ string) []string { return []string{"add", "x", "--npmrc-auth-file", c} }},
		{major: 11, command: func(c, o string) []string { return []string{"--npmrc-auth-file=" + c, "--userconfig=" + o, "add", "x"} }},
		{major: 11, env: func(c string) [2]string { return [2]string{"pnpm_config_npmrc_auth_file", c} }},
		{major: 12, command: func(c, _ string) []string { return []string{"--userconfig", c, "add", "x"} }},
		{major: 12, command: func(c, _ string) []string { return []string{"--npmrc-auth-file", c, "add", "x"} }},
		{major: 12, env: func(c string) [2]string { return [2]string{"PNPM_CONFIG_NPMRC_AUTH_FILE", c} }},
	} {
		layout := newPnpmWorkspace(t)
		company := filepath.Join(layout.root, "company.npmrc")
		other := filepath.Join(layout.root, "other.npmrc")
		writePnpmFixture(t, company, "npmrc/https-proxy.npmrc.tmpl", "http://corporate:1")
		writePnpmFixture(t, other, "npmrc/https-proxy.npmrc.tmpl", "http://other:1")
		writePnpmFixture(t, filepath.Join(layout.home(), ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://default:1")
		command := []string{"add", "x"}
		if test.command != nil {
			command = test.command(company, other)
		}
		if test.env != nil {
			pair := test.env(company)
			t.Setenv(pair[0], pair[1])
		}
		config, err := fakePnpm(t, pnpmVersions[test.major]).UpstreamProxy(command)
		if err != nil || config.HTTPSProxy != "http://corporate:1" {
			t.Errorf("pnpm %d %q: HTTPSProxy = %q (error %v), want the selected file's proxy", test.major, command, config.HTTPSProxy, err)
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
