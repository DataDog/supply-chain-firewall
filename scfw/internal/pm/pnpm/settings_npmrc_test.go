// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"path/filepath"
	"strings"
	"testing"
)

// pnpmLayout names the directories of isolatePnpmEnvironment: a project inside
// a workspace root, with the user, global, and pnpm configuration directories.
type pnpmLayout struct {
	root, workspace, project string
}

func (layout pnpmLayout) home() string   { return filepath.Join(layout.root, "home") }
func (layout pnpmLayout) prefix() string { return filepath.Join(layout.root, "prefix") }
func (layout pnpmLayout) configDir() string {
	return filepath.Join(layout.root, "xdg-config", "pnpm")
}

func newPnpmWorkspace(t *testing.T) pnpmLayout {
	t.Helper()
	root := isolatePnpmEnvironment(t)
	layout := pnpmLayout{root: root, workspace: filepath.Join(root, "parent"), project: filepath.Join(root, "parent", "project")}
	writePnpmFixture(t, filepath.Join(layout.workspace, "pnpm-workspace.yaml"), "workspace-yaml/packages.yaml")
	writePnpmFixture(t, filepath.Join(layout.project, "package.json"), "manifest/member.json")
	return layout
}

func TestNpmrcUpstreamPrecedence(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		prepare func(t *testing.T, layout pnpmLayout)
		https   string
		http    string
	}{
		{"cli beats workspace yaml", "--config.https-proxy=http://cli:1 add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, "pnpm-workspace.yaml"), "workspace-yaml/https-proxy.yaml.tmpl", "http://yaml:1")
		}, "http://cli:1", "http://cli:1"},
		{"workspace yaml beats env", "add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, "pnpm-workspace.yaml"), "workspace-yaml/https-proxy.yaml.tmpl", "http://yaml:1")
			t.Setenv("npm_config_https_proxy", "http://env:1")
		}, "http://yaml:1", "http://yaml:1"},
		{"env beats project npmrc", "add x", func(t *testing.T, l pnpmLayout) {
			t.Setenv("npm_config_https_proxy", "http://env:1")
			writePnpmFixture(t, filepath.Join(l.project, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://project:1")
		}, "http://env:1", "http://env:1"},
		{"project beats workspace npmrc", "add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.project, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://project:1")
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://workspace:1")
		}, "http://project:1", "http://project:1"},
		{"workspace beats user npmrc", "add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://workspace:1")
			writePnpmFixture(t, filepath.Join(l.home(), ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://user:1")
		}, "http://workspace:1", "http://workspace:1"},
		{"user beats global npmrc", "add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.home(), ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://user:1")
			writePnpmFixture(t, filepath.Join(l.prefix(), "etc", "npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://global:1")
		}, "http://user:1", "http://user:1"},
		{"global npmrc beats pnpm rc", "add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.prefix(), "etc", "npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://global:1")
			writePnpmFixture(t, filepath.Join(l.configDir(), "rc"), "npmrc/https-proxy.npmrc.tmpl", "http://rc:1")
		}, "http://global:1", "http://global:1"},
		{"pnpm rc", "add x", func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.configDir(), "rc"), "npmrc/https-proxy.npmrc.tmpl", "http://rc:1")
		}, "http://rc:1", "http://rc:1"},
		{"HTTPS_PROXY fallback", "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("HTTPS_PROXY", "http://upper:1")
		}, "http://upper:1", "http://upper:1"},
		{"empty https_proxy masks HTTPS_PROXY", "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("HTTPS_PROXY", "http://upper:1")
			t.Setenv("https_proxy", "")
		}, "", ""},
		{"proxy=false disables the fallback", "add x", func(t *testing.T, l pnpmLayout) {
			t.Setenv("HTTPS_PROXY", "http://upper:1")
			t.Setenv("HTTP_PROXY", "http://upper:1")
			writePnpmFixture(t, filepath.Join(l.project, ".npmrc"), "npmrc/proxy-false.npmrc")
		}, "", ""},
		{"HTTP_PROXY applies to http only", "add x", func(t *testing.T, _ pnpmLayout) {
			t.Setenv("HTTP_PROXY", "http://plain:1")
		}, "", "http://plain:1"},
		{"untrusted placeholder is dropped", "add x", func(t *testing.T, l pnpmLayout) {
			t.Setenv("SCFW_TEST_PROXY", "http://placeholder:1")
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/https-proxy-placeholder.npmrc")
			writePnpmFixture(t, filepath.Join(l.home(), ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://user:1")
		}, "http://user:1", "http://user:1"},
		{"user npmrc placeholder expands", "add x", func(t *testing.T, l pnpmLayout) {
			t.Setenv("SCFW_TEST_PROXY", "http://placeholder:1")
			writePnpmFixture(t, filepath.Join(l.home(), ".npmrc"), "npmrc/https-proxy-placeholder.npmrc")
		}, "http://placeholder:1", "http://placeholder:1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := newPnpmWorkspace(t)
			test.prepare(t, layout)
			config, err := fakePnpm(t, "10.34.9").UpstreamProxy(strings.Fields(test.command))
			if err != nil {
				t.Fatal(err)
			}
			if config.HTTPSProxy != test.https || config.HTTPProxy != test.http {
				t.Fatalf("HTTPSProxy = %q, HTTPProxy = %q, want %q and %q", config.HTTPSProxy, config.HTTPProxy, test.https, test.http)
			}
		})
	}
}

func TestNpmrcNoProxy(t *testing.T) {
	for _, test := range []struct {
		fixture, want string
	}{
		{"npmrc/noproxy.npmrc", "a.test"},
		{"npmrc/no-proxy.npmrc", "c.test"},
		{"", "b.test"},
	} {
		layout := newPnpmWorkspace(t)
		t.Setenv("NO_PROXY", "b.test")
		if test.fixture != "" {
			writePnpmFixture(t, filepath.Join(layout.project, ".npmrc"), test.fixture)
		}
		config, err := fakePnpm(t, "10.34.9").UpstreamProxy([]string{"add", "x"})
		if err != nil || config.NoProxy != test.want {
			t.Errorf("%s: NoProxy = %q (error %v), want %q", test.fixture, config.NoProxy, err, test.want)
		}
	}
}

func TestNpmrcSettingsFromWorkspaceRoot(t *testing.T) {
	layout := newPnpmWorkspace(t)
	member := filepath.Join(layout.workspace, "packages", "a")
	writePnpmFixture(t, filepath.Join(member, "package.json"), "manifest/member.json")
	writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", "http://workspace:1")
	t.Chdir(layout.workspace)
	config, err := fakePnpm(t, "10.34.9").UpstreamProxy([]string{"-C", "packages/a", "add", "x"})
	if err != nil || config.HTTPSProxy != "http://workspace:1" {
		t.Fatalf("HTTPSProxy = %q (error %v), want the workspace root's proxy", config.HTTPSProxy, err)
	}
}

func TestNpmrcUpstreamRejectsInvalidURLWithoutCredentials(t *testing.T) {
	for _, value := range []string{"socks5://user:secret@h:1", "http://user:secret@[bad", "user:secret@h:1"} {
		layout := newPnpmWorkspace(t)
		writePnpmFixture(t, filepath.Join(layout.project, ".npmrc"), "npmrc/https-proxy.npmrc.tmpl", value)
		_, err := fakePnpm(t, "10.34.9").UpstreamProxy([]string{"add", "x"})
		if err == nil || err.Error() != "unsupported or invalid pnpm upstream proxy URL" || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error = %v", value, err)
		}
	}
}
