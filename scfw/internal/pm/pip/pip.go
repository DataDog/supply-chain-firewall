// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

var pipDryRunSkipOptions = []string{"-h", "--help", "--dry-run"}

// minPipVersion is the oldest pip version whose `--dry-run --report` output
// this package relies on for resolving install targets.
var minPipVersion = pm.Version{Major: 22, Minor: 2}

// resolvePipVersion runs `<executable> --version` and parses its output,
// which is expected to look like "pip 24.0 from ... (python 3.12)".
func resolvePipVersion(ctx context.Context, executable string) (pm.Version, error) {
	output, err := exec.CommandContext(ctx, executable, "--version").Output()
	if err != nil {
		return pm.Version{}, fmt.Errorf("failed to run %q --version: %w", executable, err)
	}

	fields := strings.Fields(string(output))
	if len(fields) < 2 {
		return pm.Version{}, fmt.Errorf("unrecognized output from %q --version: %q", executable, output)
	}

	return pm.ParseVersion(fields[1])
}

type pipInstallReport struct {
	Install []pipInstallReportEntry `json:"install"`
}

type pipInstallReportEntry struct {
	Metadata struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"metadata"`
	DownloadInfo struct {
		URL string `json:"url"`
	} `json:"download_info"`
}

var PipExecutableNames = []string{"pip", "pip3"}

type Pip struct {
	executable string
	version    pm.Version
	versionErr error
}

func NewPip(ctx context.Context, name, executable string) (Pip, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return Pip{}, err
		}
	}

	// Resolved once here so that later gates (e.g. ResolveInstallTargets)
	// don't need to re-invoke the subprocess. A resolution failure is
	// deliberately not returned here: it should only fail commands that
	// actually need the version, not every use of this pip executable.
	version, versionErr := resolvePipVersion(ctx, executable)

	return Pip{executable: executable, version: version, versionErr: versionErr}, nil
}

func (pip Pip) checkVersion() error {
	if pip.versionErr != nil {
		return fmt.Errorf("%w: could not determine pip version: %v", pm.ErrUnsupportedVersion, pip.versionErr)
	}
	if pip.version.LessThan(minPipVersion) {
		return fmt.Errorf("%w: pip before v%s is not supported", pm.ErrUnsupportedVersion, minPipVersion)
	}
	return nil
}

func (pip Pip) Executable() string {
	return pip.executable
}

func (pip Pip) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, pip.Executable(), command...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

func (pip Pip) ResolveInstallTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	// pip only installs or upgrades packages via the `pip install` subcommand.
	// If `install` is not present, the command is automatically safe to run.
	if !slices.Contains(command, "install") {
		return pm.NewSet[pm.Package](), nil
	}

	if err := pip.checkVersion(); err != nil {
		return nil, err
	}

	// The presence of these options prevents the command from actually running.
	for _, opt := range pipDryRunSkipOptions {
		if slices.Contains(command, opt) {
			return pm.NewSet[pm.Package](), nil
		}
	}

	// Otherwise, this is probably a live `pip install` command.
	// To be certain, we would need to write a full parser for pip.
	dryRunArgs := append(slices.Clone(command), "--dry-run", "-qqqqq", "--report", "-")
	output, err := exec.CommandContext(ctx, pip.Executable(), dryRunArgs...).Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			// Log the failure since it's otherwise indistinguishable from a
			// legitimate no-op install.
			slog.Warn("pip dry-run install failed; treating as no install targets", "command", dryRunArgs, "stderr", string(exitErr.Stderr))
			return pm.NewSet[pm.Package](), nil
		}
		return nil, fmt.Errorf("failed to run pip dry-run install: %w", err)
	}

	var report pipInstallReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to decode pip install report: %w", err)
	}

	installTargets := pm.NewSet[pm.Package]()
	for _, entry := range report.Install {
		target, err := parsePipInstallReportEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pip install report entry: %w", err)
		}

		targetPublishDate, err := ecosystem.ResolvePublishDate(ctx, target.Ecosystem, target.Name, target.Version, target.Source)
		if err != nil {
			slog.Warn("failed to resolve package publish date", "ecosystem", target.Ecosystem, "name", target.Name, "version", target.Version, "error", err)
		} else {
			target.PublishDate = targetPublishDate
		}

		installTargets.Add(target)
	}

	return installTargets, nil
}

// parsePipInstallReportEntry converts a single pip install report entry into a pm.Package.
func parsePipInstallReportEntry(entry pipInstallReportEntry) (pm.Package, error) {
	if entry.Metadata.Name == "" {
		return pm.Package{}, errors.New("missing name for pip installation target")
	}
	if entry.Metadata.Version == "" {
		return pm.Package{}, errors.New("missing version for pip installation target")
	}

	target := pm.Package{
		Ecosystem: ecosystem.PYPI,
		Name:      entry.Metadata.Name,
		Version:   entry.Metadata.Version,
		Source:    entry.DownloadInfo.URL,
	}

	return target, nil
}
