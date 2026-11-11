// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"slices"
	"strings"
)

// Classic global options that consume the next argument; Berry only has --cwd.
var classicValueOptions = []string{
	"--cwd", "--cache-folder", "--modules-folder", "--global-folder", "--link-folder", "--preferred-cache-folder",
	"--mutex", "--network-concurrency", "--network-timeout", "--use-yarnrc", "--registry", "--proxy", "--https-proxy",
}

type yarnCommand struct {
	name, sub string
	// args follow the command name, before any "--".
	args []string
}

// parseYarnCommand skips global options to find the command. A bare yarn
// installs, so an empty name is the install command.
func parseYarnCommand(gen generation, command []string) (cmd yarnCommand, help bool, cwd string) {
	if index := slices.Index(command, "--"); index >= 0 {
		command = command[:index]
	}
	valueOptions := []string{"--cwd"}
	if gen == classic {
		valueOptions = classicValueOptions
	}
	for index := 0; index < len(command); index++ {
		argument := command[index]
		if slices.Contains([]string{"-h", "--help", "-v", "--version"}, argument) {
			help = true
		}
		if cmd.name != "" {
			continue
		}
		if !strings.HasPrefix(argument, "-") {
			cmd.name, cmd.args = argument, command[index+1:]
			continue
		}
		name, value, assigned := strings.Cut(argument, "=")
		if slices.Contains(valueOptions, name) && !assigned && index+1 < len(command) {
			index++
			value = command[index]
		}
		if name == "--cwd" {
			cwd = value
		}
	}
	for _, argument := range cmd.args {
		if !strings.HasPrefix(argument, "-") {
			cmd.sub = argument
			break
		}
	}
	return cmd, help, cwd
}

// ProxyCommandSupported selects commands that resolve or install packages.
// Everything else, such as scripts, runs directly like `uv run`. An unknown
// generation is proxied so that the proxy path reports the version error.
func (yarn Yarn) ProxyCommandSupported(command []string) bool {
	gen, err := yarn.generation()
	if err != nil {
		return true
	}
	cmd, help, _ := parseYarnCommand(gen, command)
	if help {
		return false
	}
	return installCommand(gen, cmd)
}

func installCommand(gen generation, cmd yarnCommand) bool {
	if cmd.name == "workspace" && len(cmd.args) > 1 {
		inner, _, _ := parseYarnCommand(gen, cmd.args[1:])
		return installCommand(gen, inner)
	}
	if gen == classic {
		switch cmd.name {
		case "", "install", "add", "upgrade", "upgrade-interactive", "create":
			return true
		case "global":
			return slices.Contains([]string{"add", "upgrade", "upgrade-interactive"}, cmd.sub)
		}
		return false
	}
	switch cmd.name {
	case "", "install", "add", "up", "dlx":
		return true
	case "workspaces":
		return cmd.sub == "focus" || cmd.sub == "foreach"
	}
	return false
}
