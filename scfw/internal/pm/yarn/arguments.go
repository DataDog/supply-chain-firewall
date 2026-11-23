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
	// index is the position of the command name in the arguments.
	index int
	// args follow the command name, before any "--".
	args []string
	// tail follows the command name, including any "--" and what follows it.
	tail []string
}

// parseYarnCommand skips global options to find the command. A bare yarn
// installs, so an empty name is the install command. Help and version flags
// count only before the command: after it Yarn still runs install commands,
// and create and dlx pass them to the package they execute.
func parseYarnCommand(gen generation, command []string) (cmd yarnCommand, help bool, cwd string) {
	full := command
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
			cmd.name, cmd.index, cmd.args, cmd.tail = argument, index, command[index+1:], full[index+1:]
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

// yarnKind is what a Yarn command needs from SCFW.
type yarnKind int

const (
	yarnDirect yarnKind = iota // runs a script or prints help: no proxy
	yarnOther                  // proxied, but not inspected without the proxy
	yarnFetch                  // fetches packages or Yarn code that only the proxy sees
)

// ProxyCommandSupported proxies every command except a script command: the
// script's own traffic should not be forced through the proxy.
func (yarn Yarn) ProxyCommandSupported(command []string) bool {
	return yarn.commandKind(command) != yarnDirect
}

// commandKind classifies a command line. An unknown generation is proxied so
// that the proxy path reports the version error.
func (yarn Yarn) commandKind(command []string) yarnKind {
	gen, err := yarn.generation()
	if err != nil {
		return yarnFetch
	}
	cmd, help, _ := parseYarnCommand(gen, command)
	if help {
		return yarnDirect
	}
	return classifyCommand(gen, cmd)
}

// classifyCommand follows Yarn's dispatch: a name that is not a built-in
// command runs a package script or binary. The built-in commands are those of
// Yarn 1.22 and of Yarn 4 with its bundled plugins.
func classifyCommand(gen generation, cmd yarnCommand) yarnKind {
	if cmd.name == "workspace" && len(cmd.args) > 1 {
		inner, _, _ := parseYarnCommand(gen, cmd.args[1:])
		return classifyCommand(gen, inner)
	}
	if gen == classic {
		switch cmd.name {
		case "run", "exec", "node":
			return yarnDirect
		case "", "install", "add", "remove", "upgrade", "upgrade-interactive", "upgradeInteractive", "create", "import", "licenses", "unplug":
			return yarnFetch
		case "check":
			// Without these options check resolves the dependencies.
			if !hasOption(cmd.args, "--integrity", "--verify-tree") {
				return yarnFetch
			}
		case "global":
			// Every subcommand but bin and dir resolves the global packages.
			if cmd.sub != "" && cmd.sub != "bin" && cmd.sub != "dir" {
				return yarnFetch
			}
		case "policies":
			// set-version downloads a Yarn release.
			if cmd.sub == "set-version" {
				return yarnFetch
			}
		case "set":
			// Yarn runs set version as policies set-version; any other set is a script.
			if cmd.sub == "version" {
				return yarnFetch
			}
			return yarnDirect
		case "init":
			// -2 and --install run policies set-version.
			if hasOption(cmd.args, "-2", "-i", "--install") {
				return yarnFetch
			}
		case "workspaces":
			// workspaces run starts `yarn run` in every workspace.
			if cmd.sub == "run" {
				return yarnDirect
			}
		case "access", "audit", "autoclean", "bin", "cache", "config", "dedupe", "generate-lock-entry", "generateLockEntry",
			"help", "info", "link", "list", "lockfile", "login", "logout", "outdated", "owner", "pack", "prune", "publish", "tag",
			"team", "unlink", "version", "versions", "why", "workspace":
		default:
			return yarnDirect
		}
		return yarnOther
	}
	switch cmd.name {
	case "run", "exec", "node":
		return yarnDirect
	case "", "install", "add", "remove", "up", "upgrade-interactive", "search", "dedupe", "dlx", "create", "init", "link", "unlink",
		"unplug", "patch", "rebuild":
		return yarnFetch
	case "set":
		// set version downloads a Yarn release.
		if cmd.sub == "resolution" || cmd.sub == "version" {
			return yarnFetch
		}
	case "plugin":
		// plugin import downloads a plugin bundle.
		if cmd.sub == "import" {
			return yarnFetch
		}
	case "workspaces":
		switch cmd.sub {
		case "focus":
			return yarnFetch
		case "foreach":
			return classifyCommand(gen, foreachCommand(cmd.tail))
		}
	case "version":
		// Applying a version installs.
		if cmd.sub != "check" {
			return yarnFetch
		}
	case "pack":
		if hasOption(cmd.args, "--install-if-needed") {
			return yarnFetch
		}
	case "info":
		// The manifest extra fetches every listed package.
		for index, argument := range cmd.args {
			name, value, assigned := strings.Cut(argument, "=")
			if !assigned && index+1 < len(cmd.args) {
				value = cmd.args[index+1]
			}
			if name == "--manifest" || (name == "-X" || name == "--extra") && value == "manifest" {
				return yarnFetch
			}
		}
	case "bin", "cache", "config", "constraints", "explain", "help", "npm", "patch-commit", "stage", "why", "workspace":
	default:
		return yarnDirect
	}
	return yarnOther
}

// foreachValueOptions are the `workspaces foreach` options that take a value.
var foreachValueOptions = []string{"--from", "-j", "--jobs", "--include", "--exclude"}

// foreachCommand returns the command `workspaces foreach` runs, given the
// arguments after `workspaces`.
func foreachCommand(args []string) yarnCommand {
	args = args[slices.Index(args, "foreach")+1:]
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			inner, _, _ := parseYarnCommand(berry, args[index+1:])
			return inner
		}
		if !strings.HasPrefix(argument, "-") {
			inner, _, _ := parseYarnCommand(berry, args[index:])
			return inner
		}
		// A bundle of short options such as -pj takes the value of its last one.
		name, _, assigned := strings.Cut(argument, "=")
		bundle := !strings.HasPrefix(name, "--") && strings.HasSuffix(name, "j")
		if !assigned && (bundle || slices.Contains(foreachValueOptions, name)) {
			index++
		}
	}
	return yarnCommand{}
}

// hasOption reports whether args contain one of the options, with or without
// an assigned value.
func hasOption(args []string, names ...string) bool {
	for _, argument := range args {
		if name, _, _ := strings.Cut(argument, "="); slices.Contains(names, name) {
			return true
		}
	}
	return false
}
