// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseOptionsSeparatesCommandsAndSettings(t *testing.T) {
	for _, test := range []struct {
		name, args, command, subcommand string
		options                         []option
		help                            bool
	}{
		{
			name:    "global values are not commands or retained settings",
			args:    "--cache-dir sync --color pip --preview-features install pip --cert registry.pem install project",
			command: "pip", subcommand: "install",
			options: []option{{name: "cert", value: "registry.pem", index: 8}},
		},
		{
			name:    "ordinary uv options stay opaque after command discovery",
			args:    "pip install --resolution lowest --link-mode copy --target help --python lock --directory selected project",
			command: "pip", subcommand: "install",
			options: []option{{name: "directory", value: "selected", index: 11}},
		},
		{
			name:    "project settings after unrelated option values",
			args:    "add --config-setting k=--help --project=chosen --index private=https://index.example/packages/ project",
			command: "add",
			options: []option{{name: "project", value: "chosen", index: 3, equal: true}, {name: "index", value: "private=https://index.example/packages/", index: 5}},
		},
		{
			name:    "run settings stop before child flags",
			args:    "run --with project --resolution lowest --directory selected python --directory child --config-file child.toml --help",
			command: "run",
			options: []option{{name: "directory", value: "selected", index: 6}},
		},
		{
			name:    "tool run skips values but retains only SCFW settings",
			args:    "tool run -w project -p3.12 --from=project --no-build-isolation-package project --config-file chosen.toml program --config-file child.toml --help",
			command: "tool", subcommand: "run",
			options: []option{{name: "config-file", value: "chosen.toml", index: 9}},
		},
		{
			name: "run from stdin owns the remaining arguments",
			args: "run - --directory child --help", command: "run",
		},
		{
			name: "explicit child separator",
			args: "run --with=project -- python --help --directory child", command: "run",
		},
		{
			name: "package arguments after separator stay opaque",
			args: "pip install -- --directory project --help", command: "pip", subcommand: "install",
		},
		{
			name: "help before child command",
			args: "run --with project --help", command: "run", help: true,
		},
		{
			name: "short index option",
			args: "pip install -i https://index.example/custom/ project", command: "pip", subcommand: "install",
			options: []option{{name: "index-url", value: "https://index.example/custom/", index: 3}},
		},
		{
			name: "attached short index option",
			args: "pip install -ihttps://index.example/custom/ project", command: "pip", subcommand: "install",
			options: []option{{name: "index-url", value: "https://index.example/custom/", index: 2, equal: true}},
		},
		{
			name: "missing global value", args: "--directory",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseOptions(strings.Fields(test.args))
			if got.command != test.command || got.subcommand != test.subcommand || got.help != test.help || !reflect.DeepEqual(got.options, test.options) {
				t.Fatalf("parsed %+v, want command=%q subcommand=%q help=%v options=%+v", got, test.command, test.subcommand, test.help, test.options)
			}
		})
	}
}

func TestGlobalOptionValuesDoNotSelectCommands(t *testing.T) {
	for _, flag := range []string{"--python-preference", "--python-fetch", "--preview-feature", "--preview-features"} {
		for _, equal := range []bool{false, true} {
			prefix := []string{flag, "install"}
			if equal {
				prefix = []string{flag + "=install"}
			}
			for _, command := range [][]string{{"pip", "install", "project"}, {"add", "project"}, {"sync"}, {"lock"}, {"cache", "clean"}, {"pip", "list"}} {
				args := append(append([]string{}, prefix...), command...)
				want := command[0] != "cache" && !(command[0] == "pip" && command[1] == "list")
				if got := (UV{}).ProxyCommandSupported(args); got != want {
					t.Fatalf("%v: supported=%v, want %v", args, got, want)
				}
				parsed := parseOptions(args)
				if parsed.command != command[0] || len(parsed.options) != 0 {
					t.Fatalf("%v: parsed %+v", args, parsed)
				}
			}
			args := append([]string{"pip"}, prefix...)
			args = append(args, "install", "project")
			if !(UV{}).ProxyCommandSupported(args) {
				t.Fatalf("global option between nested commands: %v", args)
			}
		}
	}
	args := strings.Fields("run --python-preference only-system --python-fetch never --preview-feature script --directory selected python --help --script child.py")
	parsed := parseOptions(args)
	if parsed.runTarget != "python" || parsed.help || len(parsed.options) != 1 || parsed.options[0].value != "selected" {
		t.Fatalf("run boundary: %+v", parsed)
	}
}

func TestRunShortOptionBoundaries(t *testing.T) {
	for _, test := range []struct {
		args, target         string
		script, module, help bool
	}{
		{args: "run -h", help: true},
		{args: "run -vh", help: true},
		{args: "run -vs entrypoint --help", target: "entrypoint", script: true},
		{args: "run -vp 3.12 -s entrypoint", target: "entrypoint", script: true},
		{args: "run -p3.12s program --script ignored", target: "program"},
		{args: "run -vm module.py", target: "module.py", module: true},
		{args: "run -vi https://index.example program --help", target: "program"},
	} {
		parsed := parseOptions(strings.Fields(test.args))
		var script, module bool
		for _, option := range parsed.options {
			script = script || option.name == "script"
			module = module || option.name == "module"
		}
		if parsed.runTarget != test.target || parsed.help != test.help || script != test.script || module != test.module {
			t.Fatalf("%s: parsed %+v", test.args, parsed)
		}
	}
}
