// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package uv integrates uv commands with invocation-scoped proxy execution.
package uv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

var ExecutableNames = []string{"uv", "uvx"}

type UV struct {
	executable string
	toolRun    bool
	proxyState *uvProxyState
}

func NewUV(_ context.Context, name, executable string) (UV, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return UV{}, err
		}
	}
	return UV{executable: executable, toolRun: name == "uvx", proxyState: &uvProxyState{}}, nil
}

func (uv UV) Executable() string { return uv.executable }

func (uv UV) ProjectDirectory(command []string) (string, error) {
	directory, err := uv.workingDirectory(command)
	if err != nil {
		return "", err
	}
	options := uv.parseOptions(command)
	if project := options.value("project", "UV_PROJECT"); project != "" {
		directory = resolvePath(directory, project)
	} else if options.command == "run" {
		targetDirectory, err := options.runConfigurationDirectory(directory)
		if err != nil {
			return "", err
		}
		if targetDirectory != "" {
			return targetDirectory, nil
		}
	}
	if filepath.Base(directory) == "pyproject.toml" {
		return physicalParent(directory)
	}
	return physicalDirectory(directory)
}

func (uv UV) workingDirectory(command []string) (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	path := uv.parseOptions(command).value("directory", "UV_WORKING_DIR")
	if path == "" {
		path = os.Getenv("UV_WORKING_DIRECTORY")
	}
	if path != "" {
		directory = resolvePath(directory, path)
	}
	return physicalDirectory(directory)
}

func resolvePath(directory, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	// filepath.Join cleans '..' before the OS can follow preceding symlinks.
	// Retain the original traversal for file reads and physical discovery.
	for part := range strings.SplitSeq(path, string(os.PathSeparator)) {
		if part == ".." {
			return directory + string(os.PathSeparator) + path
		}
	}
	return filepath.Join(directory, path)
}

func physicalDirectory(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("could not resolve uv directory")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("could not resolve uv directory")
	}
	return resolved, nil
}

// Preserve a final filename symlink: uv uses the containing directory as the
// configuration/relative-index origin, even when the file itself is a symlink.
func physicalParent(path string) (string, error) {
	directory, _ := filepath.Split(path)
	return physicalDirectory(directory)
}

func (uv UV) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, uv.executable, command...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return child.Run()
}

func (uv UV) ResolveInstallTargets(_ context.Context, command []string) (*pm.Set[pm.Package], error) {
	if uv.ProxyCommandSupported(command) {
		return nil, errors.New("uv package operations require proxy mode (set SCFW_PROXY_ENABLED=1)")
	}
	return pm.NewSet[pm.Package](), nil
}

// ProxyCommandSupported selects operations which resolve or install packages.
// Inspect command positions, never package names or arbitrary command arguments.
// uv run always executes directly, including its dependency resolution and child.
func (uv UV) ProxyCommandSupported(command []string) bool {
	options := uv.parseOptions(command)
	if options.help {
		return false
	}
	switch options.command {
	case "add", "remove", "sync", "lock", "export", "tree", "build":
		return true
	case "version":
		return (options.versionValue || options.has("bump")) && !options.has("dry-run") && !enabled(options.value("frozen", "UV_FROZEN"))
	case "venv":
		return enabled(options.value("seed", "UV_VENV_SEED"))
	case "tool":
		switch options.subcommand {
		case "install", "upgrade", "run":
			return true
		}
	case "pip":
		switch options.subcommand {
		case "install", "sync", "compile":
			return true
		}
	}
	return false
}
