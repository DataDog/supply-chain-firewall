// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"os"
	"path/filepath"
	"strings"
)

// poetryProjectDirectory selects Poetry's initial project search path. Keep
// symlinks and '..' intact until filesystem access: filepath.Abs/Join would
// change which directory a symlink followed by '..' selects. Poetry resolves
// relative --project paths, but otherwise searches the supplied logical path.
func poetryProjectDirectory(command []string) (string, error) {
	directory, err := resolvePoetryProjectDir(command)
	if err != nil {
		return "", err
	}
	if _, _, _, supplied := findPoetryDirectoryFlag(command); !supplied {
		// Path.cwd() uses the physical cwd, even when PWD retains a symlink.
		if physical, err := filepath.EvalSymlinks(directory); err == nil {
			directory = physical
		}
	}
	if !filepath.IsAbs(directory) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		directory = cwd + string(filepath.Separator) + directory
	}
	own := poetryOwnArguments(command)
	for i := 0; i < len(own); i++ {
		argument := own[i]
		project := ""
		switch {
		case argument == "--directory" || argument == "-C":
			i++
			continue
		case argument == "--project" || argument == "-P":
			if i+1 < len(own) {
				project = own[i+1]
			}
		case strings.HasPrefix(argument, "--project="):
			project = strings.TrimPrefix(argument, "--project=")
		case strings.HasPrefix(argument, "-P"):
			project = strings.TrimPrefix(strings.TrimPrefix(argument, "-P"), "=")
		}
		if project == "" {
			continue
		}
		if filepath.IsAbs(project) {
			return project, nil
		}
		directory += string(filepath.Separator) + project
		if physical, err := filepath.EvalSymlinks(directory); err == nil {
			directory = physical
		}
		break
	}
	return directory, nil
}

// poetryParentDirectory follows pathlib's lexical parents without cleaning '..'
// across symlinks. Project search paths are absolute on the supported platforms.
func poetryParentDirectory(directory string) string {
	parent, _ := filepath.Split(strings.TrimRight(directory, string(filepath.Separator)))
	parent = strings.TrimRight(parent, string(filepath.Separator))
	if parent == "" {
		return string(filepath.Separator)
	}
	return parent
}

// ProxyCommandSupported keeps global informational commands independent of
// project configuration. Only Poetry-owned options can suppress interception;
// flags passed to a run child or after '--' do not change this decision.
func (Poetry) ProxyCommandSupported(command []string) bool {
	own := poetryOwnArguments(command)
	name := ""
	for i := 0; i < len(own); i++ {
		argument := own[i]
		switch argument {
		case "--":
			return true
		case "--directory", "-C", "--project", "-P":
			i++
			continue
		case "--help", "-h", "--version", "-V":
			return false
		}
		if strings.HasPrefix(argument, "-") {
			// Cleo also accepts combined boolean short options, e.g. -vvh.
			short := strings.TrimPrefix(argument, "-")
			if strings.Trim(short, "vqnVh") == "" && strings.ContainsAny(short, "Vh") {
				return false
			}
			continue
		}
		if name == "" {
			name = argument
		}
	}
	switch name {
	case "help", "list", "about":
		return false
	case "":
		// With no command Poetry displays its command list. A truncated
		// argument list may instead hide a command after '--'; keep that proxied.
		return len(own) != len(command)
	default:
		return true
	}
}

// poetryOwnArguments excludes the executable and arguments of `poetry run`.
// Only Poetry's global directory/project options take values before the command
// or before run's executable. Returned arguments are for discovery only; the
// original command is always forwarded unchanged.
func poetryOwnArguments(command []string) []string {
	run := false
	for i := 0; i < len(command); i++ {
		argument := command[i]
		switch argument {
		case "--":
			return command[:i]
		case "--directory", "-C", "--project", "-P":
			i++
			continue
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		if run {
			return command[:i]
		}
		if argument != "run" {
			return command
		}
		run = true
	}
	return command
}
