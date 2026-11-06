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

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

var ExecutableNames = []string{"uv"}

type UV struct{ executable string }

func NewUV(_ context.Context, name, executable string) (UV, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return UV{}, err
		}
	}
	return UV{executable: executable}, nil
}

func (uv UV) Executable() string { return uv.executable }

func (uv UV) ProjectDirectory(command []string) (string, error) {
	directory, err := workingDirectory(command)
	if err != nil {
		return "", err
	}
	options := parseOptions(command)
	if project := options.value("project", "UV_PROJECT"); project != "" {
		directory = resolvePath(directory, project)
	}
	if filepath.Base(directory) == "pyproject.toml" {
		directory = filepath.Dir(directory)
	}
	return directory, nil
}

func workingDirectory(command []string) (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if path := parseOptions(command).value("directory", "UV_WORKING_DIR"); path != "" {
		directory = resolvePath(directory, path)
	}
	return directory, nil
}

func resolvePath(directory, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(directory, path)
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
func (UV) ProxyCommandSupported(command []string) bool {
	options := parseOptions(command)
	if options.help {
		return false
	}
	switch options.command {
	case "add", "remove", "sync", "lock", "export", "tree", "build", "run":
		return true
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
