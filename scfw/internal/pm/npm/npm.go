// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// npmInstallCommandAliases are all the tokens npm recognizes as the install
// subcommand. https://docs.npmjs.com/cli/v10/commands/npm-install
var npmInstallCommandAliases = []string{
	"install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
}

var npmDryRunSkipOptions = []string{"-h", "--help", "--dry-run", "--version"}

// minNpmVersion is the oldest npm version whose `--dry-run --loglevel silly`
// output this package relies on for resolving install targets.
var minNpmVersion = pm.Version{Major: 7}

// resolveNpmVersion runs `<executable> --version` and parses its output,
// which is expected to be a bare version string like "10.8.2".
func resolveNpmVersion(ctx context.Context, executable string) (pm.Version, error) {
	output, err := exec.CommandContext(ctx, executable, "--version").Output()
	if err != nil {
		return pm.Version{}, fmt.Errorf("failed to run %q --version: %w", executable, err)
	}

	return pm.ParseVersion(strings.TrimSpace(string(output)))
}

var NpmExecutableNames = []string{"npm", "npx"}

type Npm struct {
	executable string
	// npx runs `npm exec`, whose command line ends where the command it runs
	// begins; see npxOptionsEnd.
	npx                bool
	version            pm.Version
	versionErr         error
	resolvePublishDate func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error)
}

func (npm Npm) packagePublishDate(ctx context.Context, pkg pm.Package) (time.Time, error) {
	if npm.resolvePublishDate != nil {
		return npm.resolvePublishDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
	}
	return ecosystem.ResolvePublishDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
}

func NewNpm(ctx context.Context, name, executable string) (Npm, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return Npm{}, err
		}
	}

	// Resolved once here so that later gates (e.g. ResolveInstallTargets)
	// don't need to re-invoke the subprocess. A resolution failure is
	// deliberately not returned here: it should only fail commands that
	// actually need the version, not every use of this npm executable.
	version, versionErr := resolveNpmVersion(ctx, executable)

	return Npm{executable: executable, npx: filepath.Base(name) == "npx", version: version, versionErr: versionErr}, nil
}

func (npm Npm) checkVersion() error {
	if npm.versionErr != nil {
		return fmt.Errorf("%w: could not determine npm version: %v", pm.ErrUnsupportedVersion, npm.versionErr)
	}
	if npm.version.LessThan(minNpmVersion) {
		return fmt.Errorf("%w: npm before v%s is not supported", pm.ErrUnsupportedVersion, minNpmVersion)
	}
	return nil
}

func (npm Npm) Executable() string {
	return npm.executable
}

func (npm Npm) ProjectDirectory(_ []string) (string, error) {
	return os.Getwd()
}

func (npm Npm) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, npm.Executable(), command...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

var _ pm.ProxyCommandSelector = Npm{}

// ProxyCommandSupported proxies every command except a script command: npm
// downloads nothing for it, and the script's own traffic should not be forced
// through the proxy. npx may download the package it runs.
func (npm Npm) ProxyCommandSupported(command []string) bool {
	if npm.npx {
		return true
	}
	_, kind := parseNpmInvocation(command).command()
	return kind != npmScript
}

func (npm Npm) ResolveInstallTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	// Only the proxy sees what npx downloads; without it nothing would be
	// evaluated, so refuse rather than run it unchecked.
	if npm.npx {
		return nil, errors.New("npx requires proxy mode (set SCFW_PROXY_ENABLED=1)")
	}

	// Only the install subcommand (or one of its aliases) is supported for now.
	if !slices.ContainsFunc(command, func(tok string) bool { return slices.Contains(npmInstallCommandAliases, tok) }) {
		return pm.NewSet[pm.Package](), nil
	}

	if err := npm.checkVersion(); err != nil {
		return nil, err
	}

	// The presence of these options prevents the command from actually running.
	for _, opt := range npmDryRunSkipOptions {
		if slices.Contains(command, opt) {
			return pm.NewSet[pm.Package](), nil
		}
	}

	proj, err := newNpmTempProject(ctx, npm.Executable())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve npm installation targets: %w", err)
	}
	defer proj.cleanup()
	proj.resolvePublishDate = npm.packagePublishDate

	return proj.resolveInstallCommandTargets(ctx, command)
}
