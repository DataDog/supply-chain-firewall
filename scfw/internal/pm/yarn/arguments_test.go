// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"fmt"
	"testing"
)

// TestCommandClassification covers every built-in command of Yarn 1.22 and of
// Yarn 4 with its bundled plugins: direct commands run without the proxy,
// fetching commands are refused without it.
func TestCommandClassification(t *testing.T) {
	for version, cases := range map[string]map[yarnKind][][]string{
		"1.22.22": {
			yarnFetch: {
				{}, {"install"}, {"--frozen-lockfile"}, {"install", "--frozen-lockfile"}, {"add", "is-number"},
				{"--cwd", "pkg", "add", "x"}, {"--cwd=pkg", "add", "x"}, {"remove", "x"}, {"upgrade"},
				{"upgrade-interactive"}, {"upgradeInteractive"}, {"create", "react-app", "app"}, {"import"},
				{"licenses", "list"}, {"unplug", "x"}, {"global", "add", "x"}, {"global", "remove", "x"},
				{"global", "upgrade"}, {"global", "upgrade-interactive"}, {"global", "upgradeInteractive"},
				{"global", "--prefix", "/p", "add", "x"}, {"global", "list"}, {"global", "ls"},
				{"policies", "set-version", "1.22.22"}, {"set", "version", "berry"}, {"check"}, {"check", "--verbose"},
				{"init", "-2"}, {"init", "--install", "berry"}, {"init", "-i=berry"},
				{"workspace", "a", "add", "x"}, {"workspace", "a", "install"}, {"workspace", "a", "--", "install", "--help"},
				{"--silent", "set", "version", "berry"},
				// Help after the command still installs, and create runs the package.
				{"add", "x", "--help"}, {"create", "foo", "-h"}, {"create", "foo", "--version"}, {"global", "add", "x", "-h"},
				// These global options consume the next argument.
				{"--otp", "123", "add", "x"}, {"--production", "false"}, {"--emoji", "true", "add", "x"},
				{"--scripts-prepend-node-path", "true", "add", "x"},
			},
			yarnOther: {
				{"access", "public"}, {"audit"}, {"autoclean", "--init"}, {"bin"}, {"cache", "dir"}, {"check", "--integrity"},
				{"check", "--verify-tree"},
				{"config", "get", "registry"}, {"dedupe"}, {"generate-lock-entry"}, {"generateLockEntry"}, {"help"},
				{"info", "x"}, {"init", "-y"}, {"link"}, {"list"}, {"lockfile"}, {"login"}, {"logout"}, {"outdated"},
				{"owner", "list", "x"}, {"pack"}, {"policies"}, {"prune"}, {"publish"}, {"tag", "list"}, {"team", "ls", "org"},
				{"unlink"}, {"version", "--patch"}, {"versions"}, {"why", "x"}, {"workspace", "a"}, {"workspaces", "info"},
				{"global", "bin"}, {"global", "dir"}, {"workspace", "a", "outdated"},
			},
			yarnDirect: {
				{"run", "build"}, {"build"}, {"test"}, {"exec", "tsc"}, {"node", "x.js"}, {"workspace", "a", "run", "build"},
				{"workspace", "a", "build"}, {"workspaces", "run", "build"}, {"dlx", "x"}, {"--cwd", "pkg", "start"}, {"set", "x"},
				{"set", "--silent", "version"}, {"set", "--", "version"}, {"workspace", "a", "--", "run", "build"},
				{"--version"}, {"--help", "add", "x"},
			},
		},
		"4.18.1": {
			yarnFetch: {
				{}, {"install", "--immutable"}, {"--immutable"}, {"add", "-D", "x"}, {"--cwd", "pkg", "up"}, {"remove", "x"},
				{"up", "x"}, {"upgrade-interactive"}, {"search"}, {"dedupe"}, {"dlx", "cowsay"}, {"create", "vite", "app"},
				{"--cwd", "pkg", "create", "vite", "app"}, {"init"}, {"init", "-2"}, {"init", "vite"}, {"link", "../x"},
				{"unlink", "x"}, {"unplug", "x"}, {"patch", "x"}, {"rebuild"}, {"set", "resolution", "x@npm:^1.0.0", "npm:1.0.0"},
				{"set", "version", "4.18.1"}, {"set", "version", "from", "sources"}, {"plugin", "import", "x"},
				{"plugin", "import", "from", "sources"}, {"workspaces", "focus", "a"}, {"version", "patch"}, {"version", "apply"},
				{"workspace", "a", "add", "x"}, {"workspaces", "foreach", "-A", "install"},
				{"workspaces", "foreach", "--from", "a", "-pj", "4", "--include=b", "add", "x"},
				{"workspaces", "foreach", "-A", "--", "add", "x"}, {"workspace", "a", "--", "install", "--help"},
				{"workspace", "a", "workspaces", "foreach", "-A", "--", "add", "x"},
				{"workspaces", "foreach", "-A", "workspace", "b", "--", "add", "x"}, {"pack", "--install-if-needed"}, {"info", "--manifest", "x"},
				{"info", "-X", "manifest", "x"}, {"info", "--extra=manifest"},
				// dlx passes everything after the binary name to the binary.
				{"dlx", "cowsay", "-h"}, {"dlx", "cowsay", "--version"}, {"dlx", "-p", "cowsay", "cowsay", "--help"},
				{"create", "foo", "-h"},
			},
			yarnOther: {
				{"bin"}, {"cache", "clean"}, {"cache", "clear"}, {"config"}, {"config", "get", "x"}, {"config", "set", "x", "y"},
				{"config", "unset", "x"}, {"constraints"}, {"constraints", "--fix"}, {"constraints", "query", "q"},
				{"constraints", "source"}, {"explain"}, {"explain", "peer-requirements"}, {"help"}, {"info", "x"},
				{"npm", "audit"}, {"npm", "info", "x"}, {"npm", "login"}, {"npm", "logout"}, {"npm", "publish"},
				{"npm", "tag", "add", "x@1", "latest"}, {"npm", "tag", "list"}, {"npm", "tag", "remove", "x", "next"},
				{"npm", "stage", "approve"}, {"npm", "stage", "list"}, {"npm", "stage", "reject"},
				{"npm", "whoami"}, {"pack"}, {"pack", "--dry-run"}, {"info", "-X", "cache", "x"}, {"patch-commit", "dir"}, {"plugin", "check"}, {"plugin", "list"},
				{"plugin", "remove", "x"}, {"plugin", "runtime"}, {"stage"}, {"version", "check"}, {"why", "x"},
				{"workspace", "a"}, {"workspaces", "list"}, {"workspaces", "foreach", "-A", "npm", "publish"},
			},
			yarnDirect: {
				{"run", "build"}, {"start"}, {"exec", "x"}, {"node", "x"}, {"upgrade"}, {"global", "add", "x"},
				{"policies", "set-version", "x"}, {"workspace", "a", "run", "build"}, {"workspace", "a", "build"},
				{"workspaces", "foreach", "-A", "run", "build"}, {"workspaces", "foreach", "-Apt", "--since", "build"},
				{"workspaces", "foreach", "-j", "2", "--exclude", "a", "exec", "x"},
				{"workspaces", "foreach", "-A", "--", "node", "-p", "1"},
				{"workspace", "app", "workspaces", "foreach", "-A", "--", "node", "-p", "1"},
				{"workspaces", "foreach", "-A", "workspace", "b", "--", "node", "-p", "1"},
				{"workspace", "a", "--", "run", "build", "--", "--flag"}, {"-h"}, {"--version"},
			},
		},
		// An unsupported version still takes the proxy path, which reports it.
		"3.8.7": {yarnFetch: {{"run", "x"}}},
	} {
		manager := fakeYarn(t, version)
		for kind, commands := range cases {
			for _, command := range commands {
				t.Run(fmt.Sprintf("%s %q", version, command), func(t *testing.T) {
					if got, want := manager.ProxyCommandSupported(command), kind != yarnDirect; got != want {
						t.Errorf("ProxyCommandSupported = %v, want %v", got, want)
					}
					_, err := manager.ResolveInstallTargets(context.Background(), command)
					if got, want := err != nil, kind == yarnFetch; got != want {
						t.Errorf("ResolveInstallTargets error = %v, want refusal %v", err, want)
					}
				})
			}
		}
	}
}
