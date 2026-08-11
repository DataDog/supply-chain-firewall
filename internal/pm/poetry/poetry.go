// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"github.com/DataDog/scfw/scfw/internal/ecosystem"
	"github.com/DataDog/scfw/scfw/internal/pm"
)

// poetryInspectedSubcommands are the poetry subcommands that can install or
// otherwise change dependencies, and thus need their installation targets resolved.
var poetryInspectedSubcommands = []string{"add", "install", "sync", "update"}

// poetryLockRegenSubcommands are the subset of poetryInspectedSubcommands that change
// declared dependencies or their locked versions: any existing poetry.lock predates
// the change, so installation targets must be resolved by regenerating the lock
// rather than by a --dry-run of the live command.
var poetryLockRegenSubcommands = []string{"add", "update"}

var poetryDryRunSkipOptions = []string{"-V", "--version", "-h", "--help", "--dry-run"}

// minPoetryVersion is the oldest Poetry version whose CLI output and behavior
// this package relies on for resolving install targets.
var minPoetryVersion = pm.Version{Major: 1, Minor: 7}

var poetryVersionPattern = regexp.MustCompile(`Poetry \(version (.*)\)`)

// resolvePoetryVersion runs `<executable> --version` and parses its output,
// which is expected to look like "Poetry (version 1.8.3)".
func resolvePoetryVersion(ctx context.Context, executable string) (pm.Version, error) {
	output, err := exec.CommandContext(ctx, executable, "--version").Output()
	if err != nil {
		return pm.Version{}, fmt.Errorf("failed to run %q --version: %w", executable, err)
	}

	match := poetryVersionPattern.FindSubmatch(output)
	if match == nil {
		return pm.Version{}, fmt.Errorf("unrecognized output from %q --version: %q", executable, output)
	}

	return pm.ParseVersion(string(match[1]))
}

var PoetryExecutableNames = []string{"poetry"}

type Poetry struct {
	executable string
	version    pm.Version
	versionErr error
}

func NewPoetry(ctx context.Context, name, executable string) (Poetry, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return Poetry{}, err
		}
	}

	// Resolved once here so that later gates (e.g. ResolveInstallTargets)
	// don't need to re-invoke the subprocess. A resolution failure is
	// deliberately not returned here: it should only fail commands that
	// actually need the version, not every use of this poetry executable.
	version, versionErr := resolvePoetryVersion(ctx, executable)

	return Poetry{executable: executable, version: version, versionErr: versionErr}, nil
}

func (poetry Poetry) checkVersion() error {
	if poetry.versionErr != nil {
		return fmt.Errorf("%w: could not determine poetry version: %v", pm.ErrUnsupportedVersion, poetry.versionErr)
	}
	if poetry.version.LessThan(minPoetryVersion) {
		return fmt.Errorf("%w: poetry before v%s is not supported", pm.ErrUnsupportedVersion, minPoetryVersion)
	}
	return nil
}

func (poetry Poetry) Executable() string {
	return poetry.executable
}

func (poetry Poetry) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, poetry.Executable(), command...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

func (poetry Poetry) ResolveInstallTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	// Only add/install/sync/update (or a command containing one of them) can install
	// or change dependencies. If none is present, the command is automatically safe to run.
	if !slices.ContainsFunc(command, func(tok string) bool { return slices.Contains(poetryInspectedSubcommands, tok) }) {
		return pm.NewSet[pm.Package](), nil
	}

	if err := poetry.checkVersion(); err != nil {
		return nil, err
	}

	// The presence of these options prevents the command from actually running.
	for _, opt := range poetryDryRunSkipOptions {
		if slices.Contains(command, opt) {
			return pm.NewSet[pm.Package](), nil
		}
	}

	// add/update change declared dependencies or their locked versions, so any
	// existing poetry.lock predates the change: resolving their installation
	// targets requires regenerating the lock, not a --dry-run of the live command.
	if slices.ContainsFunc(command, func(tok string) bool { return slices.Contains(poetryLockRegenSubcommands, tok) }) {
		return poetry.resolveLockRegenTargets(ctx, command)
	}

	return poetry.resolveDryRunTargets(ctx, command)
}

// poetryDryRunLinePattern matches the lines of a poetry dry-run's output that
// announce a package installation, update, or downgrade.
var poetryDryRunLinePattern = regexp.MustCompile(`(Installing|Updating|Downgrading) (?:the current project: )?(.*) \((.*)\)`)

// resolveDryRunTargets resolves the installation targets of an install/sync command
// by scraping the output of a --dry-run of the command.
func (poetry Poetry) resolveDryRunTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	dryRunArgs := append(slices.Clone(command), "--dry-run")
	output, err := exec.CommandContext(ctx, poetry.Executable(), dryRunArgs...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// An erroring command does not install anything.
			return pm.NewSet[pm.Package](), nil
		}
		return nil, fmt.Errorf("failed to run poetry dry-run install: %w", err)
	}

	targets := pm.NewSet[pm.Package]()
	for _, line := range strings.Split(string(output), "\n") {
		if pkg, ok := parsePoetryDryRunLine(line); ok {
			targets.Add(pkg)
		}
	}
	if targets.Len() == 0 {
		return targets, nil
	}

	sourceMap := getPoetrySourceMap(ctx, poetry.Executable(), command)
	resolved := pm.NewSet[pm.Package]()
	for pkg := range targets.Items() {
		pkg.Source = sourceMap[poetryPackageKey{name: pkg.Name, version: pkg.Version}]

		publishDate, err := ecosystem.ResolvePublishDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
		if err != nil {
			slog.Warn("failed to resolve package publish date", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version, "error", err)
		} else {
			pkg.PublishDate = publishDate
		}

		resolved.Add(pkg)
	}
	return resolved, nil
}

// parsePoetryDryRunLine parses a single line of poetry dry-run output, returning
// the package it announces an installation/update/downgrade for, if any.
func parsePoetryDryRunLine(line string) (pm.Package, bool) {
	trimmed := strings.TrimSpace(line)
	if strings.Contains(trimmed, "Skipped") {
		return pm.Package{}, false
	}

	match := poetryDryRunLinePattern.FindStringSubmatch(trimmed)
	if match == nil {
		return pm.Package{}, false
	}

	return pm.Package{Ecosystem: ecosystem.PYPI, Name: match[2], Version: poetryTargetVersion(match[3])}, true
}

// poetryTargetVersion extracts the resulting version from a poetry dry-run line's
// parenthesized version spec, which for an update/downgrade takes the form
// "<old version> -> <new version>" rather than a bare version.
func poetryTargetVersion(versionSpec string) string {
	if _, newVersion, ok := strings.Cut(versionSpec, " -> "); ok {
		return poetryTargetVersion(newVersion)
	}
	version, _, _ := strings.Cut(versionSpec, " ")
	return version
}

// poetryPackageKey identifies a poetry.lock package entry by name and version.
type poetryPackageKey struct {
	name    string
	version string
}

// resolveLockRegenTargets resolves the installation targets of an add/update command
// by regenerating poetry.lock in a temporary copy of the project and diffing it
// against the project's existing lock, if any. A package already present in the old
// lock at the same version and source is considered unchanged; a change to either is
// reported as an installation target. A project with no existing lock has nothing to
// diff against, so every locked package is considered new.
func (poetry Poetry) resolveLockRegenTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	oldSources, newSources, err := poetry.regenerateLock(ctx, command)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// An erroring command does not install anything.
			return pm.NewSet[pm.Package](), nil
		}
		return nil, fmt.Errorf("failed to resolve poetry installation targets via lock regeneration: %w", err)
	}

	targets := pm.NewSet[pm.Package]()
	for key, source := range newSources {
		if oldSource, ok := oldSources[key]; ok && oldSource == source {
			continue
		}

		pkg := pm.Package{Ecosystem: ecosystem.PYPI, Name: key.name, Version: key.version, Source: source}

		publishDate, err := ecosystem.ResolvePublishDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
		if err != nil {
			slog.Warn("failed to resolve package publish date", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version, "error", err)
		} else {
			pkg.PublishDate = publishDate
		}

		targets.Add(pkg)
	}
	return targets, nil
}
