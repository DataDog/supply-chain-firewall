// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"path/filepath"
	"slices"
	"strings"
)

// cafileCommands accept --cafile right after the subcommand. Bun 1.2 runs a
// package script for the ones it does not yet implement, which would receive
// the option, so those start at 1.3. `bun x` and bunx read options before the
// package name only from 1.4; earlier releases run the option as a package.
var cafileCommands = map[string]int{
	"install": 2, "i": 2, "add": 2, "a": 2, "remove": 2, "rm": 2, "update": 2, "link": 2, "unlink": 2,
	"patch": 2, "patch-commit": 2, "outdated": 2, "publish": 2, "pm": 2,
	"audit": 3, "why": 3, "info": 3, "ci": 3, "x": 4,
}

// bunxMinor is the first minor release whose bunx reads --cafile.
const bunxMinor = 4

type parsedCommand struct {
	// insert is where --cafile goes, or -1 for commands that pass later
	// arguments to another program and only get environment overrides.
	insert int
	// args are the original arguments without the user's --cafile and --ca
	// options when insert is set.
	args []string
	// name is the subcommand, if any.
	name         string
	cwd, config  string
	registries   []string
	cafiles, cas []string
}

// parseCommand follows Bun's dispatch: the subcommand is the first argument
// that does not start with "-", so global options only take values in their
// "=" form, and nothing after "--" is a subcommand.
func parseCommand(minor int, bunx bool, args []string) parsedCommand {
	parsed := parsedCommand{insert: -1, args: args}
	token := -1
	// Before the subcommand, only "=" forms are options.
	var prefix []string
	for index, arg := range args {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			token = index
			break
		}
		if value, found := strings.CutPrefix(arg, "--cafile="); found {
			parsed.cafiles = append(parsed.cafiles, value)
			continue
		}
		if value, found := strings.CutPrefix(arg, "--ca="); found {
			parsed.cas = append(parsed.cas, value)
			continue
		}
		prefix = append(prefix, arg)
		if value, found := strings.CutPrefix(arg, "--cwd="); found {
			parsed.cwd = joinCwd(parsed.cwd, value)
		}
		for _, prefix := range []string{"--config=", "-c="} {
			if value, found := strings.CutPrefix(arg, prefix); found {
				parsed.config = value
			}
		}
	}
	if bunx {
		// bunx has no global options; its own are read only from 1.4.
		if minor < bunxMinor {
			return parsedCommand{insert: -1, args: args}
		}
		parsed.cafiles, parsed.cas, parsed.cwd, parsed.config = nil, nil, "", ""
		parsed.insert, parsed.args = 0, parsed.scanOptions(args, nil, 0, true)
		return parsed
	}
	if token < 0 {
		return parsed
	}
	parsed.name = args[token]
	required, found := cafileCommands[args[token]]
	if !found || minor < required {
		return parsed
	}
	insert := token + 1
	if args[token] == "pm" {
		// `bun pm --cafile x view` prints usage; the option follows the pm subcommand.
		if insert >= len(args) || strings.HasPrefix(args[insert], "-") {
			return parsed
		}
		insert++
	}
	kept := parsed.scanOptions(args, slices.Concat(prefix, args[token:insert]), insert, args[token] == "x")
	parsed.insert, parsed.args = len(prefix)+insert-token, kept
	return parsed
}

// bunxValueOptions are the options of Bun 1.4's bunx and bun x, besides
// --cafile, --ca, and --registry, that take the next argument as their value,
// which is not the package to run.
var bunxValueOptions = []string{"-p", "--package", "--cwd", "--env-file", "--minimum-release-age"}

// scanOptions appends args from index from to kept without the user's --cafile
// and --ca options, collecting them and --registry values. It stops at "--",
// and, for commands that pass later arguments to a package, at the package
// name, recording --cwd, against which Bun resolves a relative --cafile.
func (parsed *parsedCommand) scanOptions(args, kept []string, from int, stopAtPositional bool) []string {
	for index := from; index < len(args); index++ {
		arg := args[index]
		if arg == "--" || (stopAtPositional && !strings.HasPrefix(arg, "-")) {
			kept = append(kept, args[index:]...)
			break
		}
		name, value, inline := strings.Cut(arg, "=")
		if stopAtPositional && slices.Contains(bunxValueOptions, name) {
			kept = append(kept, arg)
			if !inline && index+1 < len(args) {
				index++
				value = args[index]
				kept = append(kept, value)
			}
			if name == "--cwd" {
				parsed.cwd = joinCwd(parsed.cwd, value)
			}
			continue
		}
		switch name {
		case "--cafile", "--ca", "--registry":
		default:
			kept = append(kept, arg)
			continue
		}
		if !inline {
			if index+1 >= len(args) {
				continue
			}
			index++
			value = args[index]
		}
		switch name {
		case "--cafile":
			parsed.cafiles = append(parsed.cafiles, value)
		case "--ca":
			parsed.cas = append(parsed.cas, value)
		default:
			parsed.registries = append(parsed.registries, value)
			kept = append(kept, arg)
			if !inline {
				kept = append(kept, value)
			}
		}
	}
	return kept
}

// joinCwd applies a --cwd value the way Bun does: each relative value is
// relative to the previous one, and an absolute value replaces it.
func joinCwd(current, value string) string {
	if current == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(current, value)
}

// effectiveCA returns the CA options Bun uses: the last --cafile, else every
// --ca, which Bun accumulates.
func (parsed parsedCommand) effectiveCA() (cafiles, cas []string) {
	if n := len(parsed.cafiles); n > 0 {
		return parsed.cafiles[n-1:], nil
	}
	return nil, parsed.cas
}
