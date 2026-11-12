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
	"--otp",
}

// Classic global options whose value is optional: like Yarn's option parser,
// they consume the next argument unless it is another option.
var classicOptionalValueOptions = []string{"--emoji", "--prod", "--production", "--scripts-prepend-node-path"}

type yarnCommand struct {
	name, sub string
	// args follow the command name, before any "--".
	args []string
}

// parseYarnCommand skips global options to find the command. A bare yarn
// installs, so an empty name is the install command. Help and version flags
// count only before the command: after it Yarn still runs install commands,
// and create and dlx pass them to the package they execute.
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
		if !strings.HasPrefix(argument, "-") {
			cmd.name, cmd.args = argument, command[index+1:]
			break
		}
		if slices.Contains([]string{"-h", "--help", "-v", "--version"}, argument) {
			help = true
		}
		name, value, assigned := strings.Cut(argument, "=")
		consumes := slices.Contains(valueOptions, name) || gen == classic && slices.Contains(classicOptionalValueOptions, name) &&
			index+1 < len(command) && !strings.HasPrefix(command[index+1], "-")
		if consumes && !assigned && index+1 < len(command) {
			index++
			value = command[index]
		}
		if name == "--cwd" {
			cwd = value
		}
	}
	// Yarn Classic reads --cwd anywhere; Yarn 4 also accepts `add ... --cwd <dir>`.
	switch {
	case gen == classic:
		for index := 0; index < len(cmd.args); index++ {
			name, value, assigned := strings.Cut(cmd.args[index], "=")
			if name != "--cwd" {
				continue
			}
			if !assigned && index+1 < len(cmd.args) {
				index++
				value = cmd.args[index]
			}
			cwd = value
		}
	case cmd.name == "add" && len(cmd.args) >= 2 && cmd.args[len(cmd.args)-2] == "--cwd":
		cwd = cmd.args[len(cmd.args)-1]
	}
	for index := 0; index < len(cmd.args); index++ {
		argument := cmd.args[index]
		if !strings.HasPrefix(argument, "-") {
			cmd.sub = argument
			break
		}
		if name, _, assigned := strings.Cut(argument, "="); !assigned && (name == "--prefix" || slices.Contains(valueOptions, name)) {
			index++
		}
	}
	return cmd, help, cwd
}

// ProxyCommandSupported selects commands that resolve, fetch, or install
// packages. Everything else, such as scripts, runs directly without the proxy. An
// unknown generation is proxied so that the proxy path reports the version error.
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
		case "", "install", "add", "remove", "upgrade", "upgrade-interactive", "upgradeInteractive", "create", "licenses", "import":
			return true
		case "global":
			return slices.Contains([]string{"add", "remove", "upgrade", "upgrade-interactive", "upgradeInteractive"}, cmd.sub)
		}
		return false
	}
	switch cmd.name {
	case "", "install", "add", "remove", "up", "upgrade-interactive", "dedupe", "dlx", "create", "link", "unlink", "unplug", "patch", "rebuild", "constraints":
		return true
	case "workspaces":
		return cmd.sub == "focus" || cmd.sub == "foreach"
	case "set":
		return cmd.sub == "resolution"
	}
	return false
}
