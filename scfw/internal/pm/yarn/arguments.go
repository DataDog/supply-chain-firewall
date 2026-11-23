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
	// index is the position of the command name in the arguments, or end
	// when there is none.
	index int
	// args follow the command name up to end, the first argument Yarn leaves
	// to what the command runs: "--", or for Yarn Classic the end of the
	// arguments it parses after a command in classicPreservedArguments.
	args []string
	end  int
	// workspace and inner are the name and command of `yarn workspace`.
	workspace string
	inner     []string
}

// classicPreservedArguments is how many arguments Yarn Classic parses after
// these commands on a line without "--"; it hands the rest to the script,
// package, or workspace command they run.
var classicPreservedArguments = map[string]int{"run": 1, "create": 1, "node": 0, "workspaces": 1, "workspace": 2}

// parseYarnCommand skips global options to find the command. A bare yarn
// installs, so an empty name is the install command. Help and version flags
// count only before the command: after it Yarn still runs install commands,
// and create and dlx pass them to the package they execute. cwd is the
// directory Yarn 4 runs in; Yarn Classic's is read from classicOwnArguments.
func parseYarnCommand(gen generation, command []string) (cmd yarnCommand, help bool, cwd string) {
	if gen == berry {
		cwd = berryCwd(command)
	}
	end := len(command)
	if index := slices.Index(command, "--"); index >= 0 {
		end = index
	}
	valueOptions := []string{"--cwd"}
	if gen == classic {
		valueOptions = classicValueOptions
	}
	cmd.index = end
	for index := 0; index < end; index++ {
		argument := command[index]
		if !strings.HasPrefix(argument, "-") {
			cmd.name, cmd.index = argument, index
			break
		}
		if slices.Contains([]string{"-h", "--help", "-v", "--version"}, argument) {
			help = true
		}
		if consumesValue(gen, command[:end], index) {
			index++
		}
	}
	cmd.end = end
	if preserved, found := classicPreservedArguments[cmd.name]; gen == classic && found && end == len(command) {
		if cmd.index+1+preserved < end && command[cmd.index+1+preserved] == "--into" {
			preserved += 2
		}
		cmd.end = min(cmd.index+1+preserved, end)
	}
	if cmd.index < cmd.end {
		cmd.args = command[cmd.index+1 : cmd.end]
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
	if cmd.name == "workspace" {
		cmd.workspace, cmd.inner = workspaceArguments(gen, command, cmd)
	}
	return cmd, help, cwd
}

// consumesValue reports whether the option at index takes the next argument.
// Optional values, as in Yarn Classic's option parser, are taken unless the
// next argument is another option.
func consumesValue(gen generation, arguments []string, index int) bool {
	name, _, assigned := strings.Cut(arguments[index], "=")
	if assigned || index+1 >= len(arguments) {
		return false
	}
	if gen == berry {
		return name == "--cwd"
	}
	return slices.Contains(classicValueOptions, name) ||
		slices.Contains(classicOptionalValueOptions, name) && !strings.HasPrefix(arguments[index+1], "-")
}

// workspaceArguments splits `yarn workspace` into the workspace name and its
// command. Yarn Classic parses options among the two arguments it keeps, so
// `yarn workspace --cwd dir a add x` runs `add x` in workspace a of dir.
// With a "--" it parses the whole line; the separator is kept so the
// arguments after it stay arguments.
func workspaceArguments(gen generation, command []string, cmd yarnCommand) (string, []string) {
	var arguments []string
	switch {
	case gen == berry || cmd.end < len(command) && command[cmd.end] == "--":
		if len(cmd.args) < 2 {
			return "", nil
		}
		arguments = command[cmd.index+1:]
	default:
		for index := 0; index < len(cmd.args); index++ {
			switch {
			case !strings.HasPrefix(cmd.args[index], "-"):
				arguments = append(arguments, cmd.args[index])
			case consumesValue(classic, cmd.args, index):
				index++
			}
		}
		arguments = append(arguments, command[cmd.end:]...)
	}
	if len(arguments) < 2 {
		return "", nil
	}
	return arguments[0], arguments[1:]
}

// classicOwnArguments returns the arguments Yarn Classic parses itself: the
// options before the command and the arguments the command keeps.
func classicOwnArguments(command []string, cmd yarnCommand) []string {
	return slices.Concat(command[:cmd.index], cmd.args)
}

// berryCwd returns the directory Yarn 4 accepts: a --cwd as the very first
// argument, or the last two arguments of a command line starting with add.
// Yarn 4 rejects a --cwd anywhere else.
func berryCwd(command []string) string {
	switch {
	case len(command) >= 2 && command[0] == "--cwd":
		return command[1]
	case len(command) >= 1 && strings.HasPrefix(command[0], "--cwd="):
		return strings.TrimPrefix(command[0], "--cwd=")
	case len(command) >= 3 && command[0] == "add" && command[len(command)-2] == "--cwd":
		return command[len(command)-1]
	}
	return ""
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
	if cmd.name == "workspace" && len(cmd.inner) > 0 {
		inner, _, _ := parseYarnCommand(gen, cmd.inner)
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
