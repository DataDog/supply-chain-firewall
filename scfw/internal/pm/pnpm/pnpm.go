// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

var ExecutableNames = []string{"pnpm", "pnpx", "pn", "pnx"}

type Pnpm struct {
	executable string
	// dlx is set for pnpx and pnx, which run `pnpm dlx`.
	dlx        bool
	installed  pm.Version
	versionErr error
}

// versionProbeEnvironment stops pnpm from switching to a pinned version, which
// it would download outside the proxy, while it reports its own version.
var versionProbeEnvironment = []string{
	"npm_config_manage_package_manager_versions=false",
	"pnpm_config_manage_package_manager_versions=false",
	"pnpm_config_pm_on_fail=ignore",
	"npm_config_package_manager_strict=false",
	"COREPACK_ENABLE_STRICT=0",
}

// NewPnpm records the installed pnpm version, probed from an empty directory so
// that no project pin or config dependency is downloaded. A version failure
// only fails commands that need it.
func NewPnpm(ctx context.Context, name, executable string) (Pnpm, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return Pnpm{}, err
		}
	}
	base := filepath.Base(name)
	manager := Pnpm{executable: executable, dlx: base == "pnpx" || base == "pnx"}
	manager.installed, manager.versionErr = probeVersion(ctx, versionExecutable(executable))
	return manager, nil
}

// versionExecutable returns the pnpm entry point beside a pnpx or pnx one:
// those run `pnpm dlx`, which rejects --version.
func versionExecutable(executable string) string {
	dir, base := filepath.Split(executable)
	for dlx, pnpm := range map[string]string{"pnpx": "pnpm", "pnx": "pn"} {
		if suffix, found := strings.CutPrefix(base, dlx); found {
			if sibling := filepath.Join(dir, pnpm+suffix); regularFile(sibling) {
				return sibling
			}
			if found, err := exec.LookPath("pnpm"); err == nil {
				return found
			}
		}
	}
	return executable
}

func probeVersion(ctx context.Context, executable string) (pm.Version, error) {
	dir, err := os.MkdirTemp("", "scfw-pnpm-version-")
	if err != nil {
		return pm.Version{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	probe := exec.CommandContext(ctx, executable, "--version")
	probe.Dir = dir
	probe.Env = append(os.Environ(), versionProbeEnvironment...)
	output, err := probe.Output()
	if err != nil {
		return pm.Version{}, err
	}
	return pm.ParseVersion(strings.TrimSpace(string(output)))
}

// major returns the pnpm major version that will run command. pnpm 10 and
// later switch to the version the project pins unless switching is disabled.
// The project directory comes from command, parsed the way the installed pnpm
// reads it and again by the pinned version when that differs.
func (p Pnpm) major(command []string) (int, error) {
	if p.versionErr != nil {
		return 0, fmt.Errorf("%w: could not determine pnpm version: %v", pm.ErrUnsupportedVersion, p.versionErr)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, errors.New("could not resolve pnpm directory")
	}
	version := p.effectiveVersion(cwd, p.installed.Major, command)
	if version.Major != p.installed.Major {
		version = p.effectiveVersion(cwd, version.Major, command)
	}
	if version.Major < 10 || version.Major > 12 {
		return 0, fmt.Errorf("%w: pnpm %s is not supported (supported: 10.x, 11.x and 12.x)", pm.ErrUnsupportedVersion, version)
	}
	return version.Major, nil
}

func (p Pnpm) effectiveVersion(cwd string, parser int, command []string) pm.Version {
	parsed := parseCommand(parser, p.dlx, command)
	dir := cwd
	if parsed.dir != "" {
		dir = parsed.dir
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
	}
	root := configRoot(dir)
	if pinned, found := pinnedVersion(root); found && p.installed.Major >= 10 && !p.switchingDisabled(root, parsed) {
		return pinned
	}
	return p.installed
}

// configRoot mirrors pnpm's project root: the nearest directory at or above dir
// with pnpm-workspace.yaml, else the nearest with package.json, else dir.
func configRoot(dir string) string {
	nearestManifest := ""
	for current := dir; ; current = filepath.Dir(current) {
		if regularFile(filepath.Join(current, "pnpm-workspace.yaml")) {
			return current
		}
		if nearestManifest == "" && regularFile(filepath.Join(current, "package.json")) {
			nearestManifest = current
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	if nearestManifest != "" {
		return nearestManifest
	}
	return dir
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// pinnedVersion reads the pnpm version root's package.json pins through
// packageManager or devEngines.packageManager. A malformed manifest pins
// nothing, so the installed version decides.
func pinnedVersion(root string) (pm.Version, bool) {
	data, err := nodeproxy.ReadConfigFile(filepath.Join(root, "package.json"))
	if err != nil {
		return pm.Version{}, false
	}
	var manifest struct {
		PackageManager string `json:"packageManager"`
		DevEngines     struct {
			PackageManager json.RawMessage `json:"packageManager"`
		} `json:"devEngines"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return pm.Version{}, false
	}
	value := ""
	if name, version, found := strings.Cut(manifest.PackageManager, "@"); found && name == "pnpm" {
		value = version
	} else {
		var engine struct{ Name, Version string }
		if json.Unmarshal(manifest.DevEngines.PackageManager, &engine) == nil && engine.Name == "pnpm" {
			value = engine.Version
		}
	}
	value, _, _ = strings.Cut(value, "+")
	version, err := pm.ParseVersion(value)
	return version, err == nil
}

// switchingDisabled reports settings that keep the installed pnpm running a
// pinned project. Each major honours its own: pnpm 10 only
// manage-package-manager-versions from npm_config_* and Corepack; pnpm 11
// only pm-on-fail; pnpm 12 both, from pnpm_config_* or npm_config_*. From
// pnpm 11, `with current` runs the installed pnpm.
func (p Pnpm) switchingDisabled(root string, parsed parsedCommand) bool {
	environ := os.Environ()
	npmEnvironment := nodeproxy.EnvironmentConfig(environ)
	pnpmEnvironment := pnpmEnvironmentConfig(environ, p.installed.Major)
	unmanaged := func(values []string) bool {
		value := nodeproxy.LastValue(values)
		return strings.EqualFold(value, "false") || value == "0"
	}
	noDownload := func(values []string) bool {
		value := nodeproxy.LastValue(values)
		return value != "" && value != "download"
	}
	switch p.installed.Major {
	case 10:
		return unmanaged(npmEnvironment["manage-package-manager-versions"]) || os.Getenv("COREPACK_ROOT") != ""
	case 11:
		if parsed.withCurrent || noDownload(parsed.network["pm-on-fail"]) || noDownload(pnpmEnvironment["pm-on-fail"]) {
			return true
		}
	default:
		if parsed.withCurrent || noDownload(parsed.network["pm-on-fail"]) || noDownload(pnpmEnvironment["pm-on-fail"]) ||
			unmanaged(parsed.network["manage-package-manager-versions"]) || unmanaged(pnpmEnvironment["manage-package-manager-versions"]) ||
			unmanaged(npmEnvironment["manage-package-manager-versions"]) {
			return true
		}
	}
	data, err := nodeproxy.ReadConfigFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return false
	}
	var settings struct {
		PmOnFail string `yaml:"pmOnFail"`
	}
	return yaml.Unmarshal(data, &settings) == nil && settings.PmOnFail != "" && settings.PmOnFail != "download"
}

func (p Pnpm) Executable() string {
	return p.executable
}

func (p Pnpm) ProjectDirectory(_ []string) (string, error) {
	return os.Getwd()
}

func (p Pnpm) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, p.executable, command...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return child.Run()
}

func (p Pnpm) ResolveInstallTargets(_ context.Context, command []string) (*pm.Set[pm.Package], error) {
	if p.ProxyCommandSupported(command) {
		return nil, errors.New("pnpm package operations require proxy mode (set SCFW_PROXY_ENABLED=1)")
	}
	return pm.NewSet[pm.Package](), nil
}
