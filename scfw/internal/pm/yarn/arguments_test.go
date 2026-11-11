// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"fmt"
	"testing"
)

func TestProxyCommandSupported(t *testing.T) {
	for version, cases := range map[string]map[bool][][]string{
		"1.22.22": {
			true: {
				{}, {"install"}, {"--frozen-lockfile"}, {"install", "--frozen-lockfile"}, {"add", "is-number"},
				{"--cwd", "pkg", "add", "x"}, {"--cwd=pkg", "add", "x"}, {"upgrade"}, {"upgrade-interactive"},
				{"global", "add", "x"}, {"create", "react-app", "app"}, {"workspace", "a", "add", "x"},
			},
			false: {
				{"run", "build"}, {"build"}, {"test"}, {"exec", "tsc"}, {"node", "x.js"}, {"info", "x"}, {"audit"},
				{"global", "list"}, {"add", "x", "--help"}, {"--version"}, {"workspace", "a", "run", "build"}, {"dlx", "x"},
			},
		},
		"4.18.1": {
			true: {
				{}, {"install", "--immutable"}, {"--immutable"}, {"add", "-D", "x"}, {"up", "x"}, {"dlx", "cowsay"},
				{"workspaces", "focus", "a"}, {"workspaces", "foreach", "-A", "install"}, {"--cwd", "pkg", "up"},
				{"workspace", "a", "add", "x"},
			},
			false: {
				{"run", "build"}, {"start"}, {"exec", "x"}, {"node", "x"}, {"npm", "info", "x"}, {"npm", "audit"},
				{"set", "version", "4.18.1"}, {"plugin", "import", "x"}, {"upgrade"}, {"workspace", "a", "run", "build"}, {"-h"},
			},
		},
		// An unsupported version still takes the proxy path, which reports it.
		"3.8.7": {true: {{"run", "x"}}},
	} {
		manager := fakeYarn(t, version)
		for want, commands := range cases {
			for _, command := range commands {
				t.Run(fmt.Sprintf("%s %q", version, command), func(t *testing.T) {
					if got := manager.ProxyCommandSupported(command); got != want {
						t.Fatalf("ProxyCommandSupported = %v, want %v", got, want)
					}
				})
			}
		}
	}
}
