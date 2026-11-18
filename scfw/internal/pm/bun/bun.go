// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

var ExecutableNames = []string{"bun", "bunx"}

type Bun struct {
	executable string
	// bunx is set for the bunx entry point, which runs `bun x`.
	bunx       bool
	installed  pm.Version
	versionErr error
}

// NewBun records the installed Bun version. A version failure only fails
// commands that need it.
func NewBun(ctx context.Context, name, executable string) (Bun, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return Bun{}, err
		}
	}
	manager := Bun{executable: executable, bunx: filepath.Base(name) == "bunx"}
	manager.installed, manager.versionErr = probeVersion(ctx, versionExecutable(executable, manager.bunx))
	return manager, nil
}

// versionExecutable returns the bun binary a bunx entry point links to; bunx
// would run --version as a package.
func versionExecutable(executable string, bunx bool) string {
	if !bunx {
		return executable
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil && filepath.Base(resolved) != "bunx" {
		return resolved
	}
	if sibling := filepath.Join(filepath.Dir(executable), "bun"); regularFile(sibling) {
		return sibling
	}
	if found, err := exec.LookPath("bun"); err == nil {
		return found
	}
	return executable
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func probeVersion(ctx context.Context, executable string) (pm.Version, error) {
	dir, err := os.MkdirTemp("", "scfw-bun-version-")
	if err != nil {
		return pm.Version{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	probe := exec.CommandContext(ctx, executable, "--version")
	probe.Dir = dir
	output, err := probe.Output()
	if err != nil {
		return pm.Version{}, err
	}
	return pm.ParseVersion(strings.TrimSpace(string(output)))
}

func (b Bun) checkVersion() error {
	if b.versionErr != nil {
		return fmt.Errorf("%w: could not determine bun version: %v", pm.ErrUnsupportedVersion, b.versionErr)
	}
	if b.installed.Major != 1 || b.installed.Minor < 2 {
		return fmt.Errorf("%w: bun %s is not supported (supported: 1.2 and later 1.x)", pm.ErrUnsupportedVersion, b.installed)
	}
	return nil
}

func (b Bun) Executable() string {
	return b.executable
}

func (b Bun) ProjectDirectory(_ []string) (string, error) {
	return os.Getwd()
}

func (b Bun) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, b.executable, command...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return child.Run()
}

// ResolveInstallTargets refuses every command: any Bun command can download
// packages, including the auto-install of `bun run` and `bun <file>`.
func (b Bun) ResolveInstallTargets(_ context.Context, _ []string) (*pm.Set[pm.Package], error) {
	return nil, errors.New("bun commands require proxy mode (set SCFW_PROXY_ENABLED=1)")
}
