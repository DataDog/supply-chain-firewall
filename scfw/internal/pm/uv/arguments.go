// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"os"
	"strings"
)

type option struct {
	name, value string
	// Position of the value, or the option itself for --option=value.
	index int
	equal bool
}

type commandOptions struct {
	options             []option
	command, subcommand string
	help                bool
}

func (o commandOptions) value(name, environment string) string {
	for i := len(o.options) - 1; i >= 0; i-- {
		if o.options[i].name == name {
			return o.options[i].value
		}
	}
	return os.Getenv(environment)
}

func parseOptions(args []string) commandOptions {
	var result commandOptions
	var index int
	result.command, index = result.nextCommand(args, 0)
	if result.command == "pip" || result.command == "tool" {
		result.subcommand, index = result.nextCommand(args, index)
	}
	runsChild := result.command == "run" || (result.command == "tool" && result.subcommand == "run")
	for index < len(args) && args[index] != "--" {
		if runsChild && (args[index] == "-" || !strings.HasPrefix(args[index], "-")) {
			break // All remaining arguments belong to the child command.
		}
		next := result.readOption(args, index)
		if runsChild && next == index+1 {
			next = runOptionEnd(args[index], index)
		}
		index = next
	}
	return result
}

// Discover only command positions. Global option values such as --directory pip
// must not become command names. Supported operations are selected in uv.go.
func (o *commandOptions) nextCommand(args []string, index int) (string, int) {
	for index < len(args) {
		if args[index] == "--" {
			index++
			if index == len(args) {
				break
			}
			return args[index], index + 1
		}
		if !strings.HasPrefix(args[index], "-") {
			return args[index], index + 1
		}
		index = o.readOption(args, index)
	}
	return "", index
}

// Read only SCFW settings, plus value-taking global flags that must be consumed
// during command discovery. Other uv options and positional arguments stay opaque.
func (o *commandOptions) readOption(args []string, index int) int {
	argument := args[index]
	if !strings.HasPrefix(argument, "-") {
		return index + 1
	}
	name, value, equal := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
	if strings.HasPrefix(argument, "-i") {
		name, value, equal = "index-url", argument[2:], len(argument) > 2
	}
	if name == "trusted-host" {
		name = "allow-insecure-host"
	}
	switch name {
	case "help", "version", "-h", "-V":
		o.help = true
		return index + 1
	case "no-config":
		o.options = append(o.options, option{name: name, value: "true", index: index})
		return index + 1
	case "directory", "project", "config-file", "allow-insecure-host", "cert",
		"index", "default-index", "index-url", "extra-index-url",
		"cache-dir", "color", "preview-features":
		if !equal {
			index++
			if index == len(args) {
				return index
			}
			value = args[index]
		}
		if name != "cache-dir" && name != "color" && name != "preview-features" {
			o.options = append(o.options, option{name: name, value: value, index: index, equal: equal})
		}
	}
	return index + 1
}

// Only run commands need the arity of uv options unrelated to SCFW: their first
// positional argument starts a child command whose flags must not be inspected.
func runOptionEnd(argument string, index int) int {
	switch argument {
	case "--with", "--with-editable", "--with-requirements", "--env-file", "--from",
		"--extra", "--no-extra", "--group", "--no-group", "--only-group", "--package", "--no-editable-package",
		"--python", "--python-platform", "--find-links", "--constraints", "--build-constraints", "--overrides",
		"--index-strategy", "--keyring-provider", "--upgrade-package", "--upgrade-group",
		"--resolution", "--prerelease", "--prerelease-package", "--fork-strategy", "--torch-backend",
		"--exclude-newer", "--exclude-newer-package", "--no-sources-package",
		"--reinstall-package", "--link-mode", "--refresh-package", "--config-setting", "--config-settings-package",
		"--no-build-isolation-package", "--no-build-package", "--no-binary-package",
		"-p", "-w", "-f", "-C", "-P", "-c", "-b":
		return index + 2
	}
	return index + 1
}
