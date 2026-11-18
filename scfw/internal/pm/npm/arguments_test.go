// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"slices"
	"strings"
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
		// npm's parser gives a boolean flag a following literal true/false as its
		// value, and treats any other =value as the bare flag.
		{"global equals true", []string{"--global=true", "install"}, []npmOption{{"global", "true"}}},
		{"global equals false", []string{"--global=false", "install"}, []npmOption{{"global", "false"}}},
		{"global equals other value", []string{"--global=1"}, []npmOption{{"global", "true"}}},
		{"global equals empty", []string{"--global="}, []npmOption{{"global", "true"}}},
		{"global then true", []string{"--global", "true", "install"}, []npmOption{{"global", "true"}}},
		{"global then false", []string{"--global", "false", "install"}, []npmOption{{"global", "false"}}},
		{"global shorthand then false", []string{"-g", "false", "install"}, []npmOption{{"global", "false"}}},
		{"shorthand group -gD", []string{"-gD", "install"}, []npmOption{{"global", "true"}}},
		{"shorthand group -Dg", []string{"install", "-Dg"}, []npmOption{{"global", "true"}}},
		{"shorthand group with a value letter", []string{"-gC", "/tmp", "install"}, []npmOption{{"global", "true"}}},
		{"not a shorthand group", []string{"-gx"}, nil},
		{"shorthand group without g", []string{"-Dq"}, nil},
		{"global shorthand equals true", []string{"-g=true"}, []npmOption{{"global", "true"}}},
		{"global shorthand equals false", []string{"-g=false"}, []npmOption{{"global", "false"}}},
		// npm negates the literal that follows: --no-global false is --global.
		{"no-global then false", []string{"--no-global", "false", "install"}, []npmOption{{"global", "true"}}},
		{"no-global then true", []string{"--no-global", "true"}, []npmOption{{"global", "false"}}},
		{"no-global equals false", []string{"--no-global=false"}, []npmOption{{"global", "true"}}},
		{"no-global equals true", []string{"--no-global=true"}, []npmOption{{"global", "false"}}},
		{"global then command", []string{"--global", "install"}, []npmOption{{"global", "true"}}},
		{"no-global", []string{"--no-global", "install"}, []npmOption{{"global", "false"}}},
		{"workspaces bare", []string{"--workspaces", "install"}, []npmOption{{"workspaces", "true"}}},
		{"workspaces equals false", []string{"--workspaces=false"}, []npmOption{{"workspaces", "false"}}},
		{"workspaces then false", []string{"--workspaces", "false", "install"}, []npmOption{{"workspaces", "false"}}},
		{"workspaces then true", []string{"--workspaces", "true"}, []npmOption{{"workspaces", "true"}}},
		{"no-workspaces", []string{"--no-workspaces", "install"}, []npmOption{{"workspaces", "false"}}},
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

// Only a plain script command runs without the proxy. Anything unusual stays
// proxied, so no option spelling can hide a command that fetches packages.
func TestNpmProxyCommandSupported(t *testing.T) {
	for want, commands := range map[bool][]string{
		false: {
			"run build", "run add", "run-script x", "rum x", "urn x", "test", "t", "tst", "start", "stop", "restart",
			"run build -- --foo", "--silent run build", "-s run build", "-s -g run x", "--loglevel=warn test",
			"--foo=bar start", "--ignore-scripts run build",
			// npm runs a script whichever word is the command.
			"-- run build", "--foo run start", "--prefix run test",
		},
		true: {
			"install x", "ci", "exec cowsay", "x cowsay", "update", "view x", "pack x", "diff a b", "help install", "ls",
			"", "--version", "--help", "-h", "init -w pkg", "version patch -w pkg", "rest",
			// An option that may take a value could hide the command, so these stay proxied.
			"-C docs ci", "-C docs run build", "--prefix web run build", "-w api test", "--regis https://r/ ci",
			"--no-color run build", "--color always run build", "--loglevel silly run build", "--prefix run install",
			"--prefix test -- install evil", "-C start -- ci",
		},
	} {
		for _, command := range commands {
			t.Run(command, func(t *testing.T) {
				if got := (Npm{}).ProxyCommandSupported(strings.Fields(command)); got != want {
					t.Fatalf("ProxyCommandSupported(%q) = %v, want %v", command, got, want)
				}
			})
		}
	}
	// npx may download the package it runs, whatever the arguments say.
	for _, command := range []string{"cowsay", "--yes cowsay --help", "--help", "run build"} {
		if !(Npm{npx: true}).ProxyCommandSupported(strings.Fields(command)) {
			t.Errorf("npx %q must be proxied", command)
		}
	}
}

func TestNpmInvocationCommand(t *testing.T) {
	for _, test := range []struct {
		command string
		name    string
		kind    npmKind
		noop    bool
	}{
		{"", "", npmOther, false},
		{"install react", "install", npmInstall, false},
		{"isntal react", "install", npmInstall, false},
		{"-g false install react", "install", npmInstall, false},
		{"--dry-run false install react", "install", npmInstall, false},
		{"install --dry-run react", "install", npmInstall, true},
		{"--version", "", npmOther, true},
		{"run build", "run", npmScript, false},
		{"run install", "run", npmScript, false},
		{"-- install react", "install", npmInstall, false},
		{"exec -- tsc --help", "exec", npmFetch, false},
		{"ci --help false", "ci", npmFetch, false},
		{"audit", "audit", npmOther, false},
		{"audit --audit-level high fix", "audit", npmFetch, false},
		{"cache ls", "cache", npmOther, false},
		{"cache add x", "cache", npmFetch, false},
		{"init -y", "init", npmOther, false},
		{"create vite", "init", npmFetch, false},
		{"view react", "view", npmOther, false},
		// After an option that may take a value, the most demanding word is the command.
		{"--prefix run install", "install", npmInstall, false},
		{"--prefix web ci", "ci", npmFetch, false},
		{"--prefix run test", "run", npmScript, false},
		{"--loglevel silly run build", "silly", npmOther, false},
		{"--color always ci", "ci", npmFetch, false},
		{"--cache /x cache add y", "cache", npmFetch, false},
	} {
		t.Run(test.command, func(t *testing.T) {
			invocation := parseNpmInvocation(strings.Fields(test.command))
			name, kind := invocation.command()
			if name != test.name || kind != test.kind || invocation.noop != test.noop {
				t.Fatalf("command() = %q, %d, noop %v; want %q, %d, noop %v", name, kind, invocation.noop, test.name, test.kind, test.noop)
			}
		})
	}
}

// The expectations below were measured by running npx-cli.js's own option loop.
func TestNpxOptionsEnd(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, 0},
		{"positional first", []string{"cowsay", "hi"}, 0},
		{"switch", []string{"--yes", "cowsay", "--proxy", "x"}, 1},
		{"switch shorthand", []string{"-y", "cowsay"}, 1},
		{"package option", []string{"--package", "cowsay", "cowsay"}, 2},
		{"package shorthand", []string{"-p", "cowsay", "cowsay"}, 2},
		{"registry value", []string{"--registry", "https://r/", "cowsay"}, 2},
		{"registry assigned", []string{"--registry=https://r/", "cowsay"}, 1},
		{"registry shorthand word", []string{"--reg", "https://r/", "cowsay"}, 2},
		{"option followed by an option", []string{"--loglevel", "--yes", "cowsay"}, 2},
		{"loglevel shorthand", []string{"-q", "cowsay"}, 1},
		{"call option without a command", []string{"--call", "echo hi"}, 2},
		{"no-install", []string{"--no-install", "cowsay"}, 1},
		{"workspaces shorthand word", []string{"--ws", "cowsay"}, 1},
		{"workspace shorthand", []string{"-w", "a", "cowsay"}, 2},
		{"prefix shorthand assigned", []string{"-C=/tmp", "cowsay"}, 1},
		{"shell option", []string{"--shell", "sh", "cowsay"}, 2},
		{"removed option takes a value", []string{"--npm", "x", "cowsay"}, 2},
		{"removed switch", []string{"--always-spawn", "cowsay"}, 1},
		{"removed shorthand takes a value", []string{"-n", "x", "cowsay"}, 2},
		// npx is not aware of no-yes, so it takes the next argument as its value.
		{"no-yes", []string{"--no-yes", "cowsay", "x"}, 2},
		// npx expands -y=true to --yes true, which hands true to the command.
		{"shorthand with a value", []string{"-y=true", "cowsay"}, 0},
		{"separator", []string{"--yes", "--", "cowsay"}, 1},
		{"options only", []string{"--yes"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := npxOptionsEnd(test.args); got != test.want {
				t.Fatalf("npxOptionsEnd(%q) = %d, want %d", test.args, got, test.want)
			}
		})
	}
}

func TestWithoutGlobalOptions(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{"short flag", []string{"install", "-g", "react"}, []string{"install", "react"}},
		{"long flag", []string{"install", "--global", "react"}, []string{"install", "react"}},
		{"long flag then false", []string{"install", "--global", "false", "react"}, []string{"install", "react"}},
		{"short flag then true", []string{"install", "-g", "true", "react"}, []string{"install", "react"}},
		{"no-global then false", []string{"install", "--no-global", "false", "react"}, []string{"install", "react"}},
		{"assigned booleans", []string{"install", "-g=true", "--global=false", "--no-global=true", "react"}, []string{"install", "react"}},
		// npm reads any other assigned value as the next positional argument.
		{"assigned value is a package", []string{"install", "-g=evil"}, []string{"install", "evil"}},
		{"long assigned value is a package", []string{"install", "--global=evil"}, []string{"install", "evil"}},
		{"negated assigned value is a package", []string{"install", "--no-global=evil"}, []string{"install", "evil"}},
		{"group -gD", []string{"install", "-gD", "react"}, []string{"install", "-D", "react"}},
		{"group -Dg", []string{"install", "-Dg", "react"}, []string{"install", "-D", "react"}},
		{"group with a value letter", []string{"install", "-gC", "/tmp", "react"}, []string{"install", "-C", "/tmp", "react"}},
		{"group of only g", []string{"install", "-gg", "react"}, []string{"install", "react"}},
		{"not a group", []string{"install", "-gx", "react"}, []string{"install", "-gx", "react"}},
		{"after separator", []string{"exec", "--", "node", "-g"}, []string{"exec", "--", "node", "-g"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := slices.Clone(test.args)
			if got := withoutGlobalOptions(test.args); !slices.Equal(got, test.want) {
				t.Fatalf("withoutGlobalOptions(%q) = %q, want %q", test.args, got, test.want)
			}
			if !slices.Equal(test.args, original) {
				t.Fatalf("input was mutated: %q", test.args)
			}
		})
	}
}
