// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/DataDog/scfw/scfw/internal/ecosystem"
	"github.com/DataDog/scfw/scfw/internal/pm"
)

// testTarget is a small, stable, pinned PyPI package used as a dry-run
// install target. Pinning avoids resolution drift over time.
const testTarget = "six==1.16.0"

// testTargetPackage is the expected resolved installation target for testTarget,
// including its real PyPI source URL and publication date (confirmed against the
// PyPI registry), so that it can be asserted by full equality rather than field by field.
var testTargetPackage = pm.Package{
	Ecosystem:   ecosystem.PYPI,
	Name:        "six",
	Version:     "1.16.0",
	Source:      "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl",
	PublishDate: time.Date(2021, 5, 5, 14, 18, 18, 379524000, time.UTC),
}

// requireSystemPip locates a real pip executable in the test environment,
// skipping the test if none is available.
func requireSystemPip(t *testing.T) Pip {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, name := range PipExecutableNames {
		if _, err := exec.LookPath(name); err != nil {
			continue
		}
		pip, err := NewPip(ctx, name, "")
		if err != nil {
			t.Fatalf("NewPip(%q) failed: %v", name, err)
		}
		return pip
	}

	t.Skip("no pip executable found in PATH")
	return Pip{}
}

func TestPipCheckVersion_TooOld(t *testing.T) {
	pip := Pip{version: pm.Version{Major: minPipVersion.Major - 1}}
	err := pip.checkVersion()
	if !errors.Is(err, pm.ErrUnsupportedVersion) {
		t.Fatalf("checkVersion() = %v, want error wrapping ErrUnsupportedVersion", err)
	}
}

func TestPipCheckVersion_UnresolvedVersion(t *testing.T) {
	pip := Pip{versionErr: errors.New("boom")}
	err := pip.checkVersion()
	if !errors.Is(err, pm.ErrUnsupportedVersion) {
		t.Fatalf("checkVersion() = %v, want error wrapping ErrUnsupportedVersion", err)
	}
}

func TestPipCheckVersion_Supported(t *testing.T) {
	pip := Pip{version: minPipVersion}
	if err := pip.checkVersion(); err != nil {
		t.Fatalf("checkVersion() returned unexpected error: %v", err)
	}
}

func TestNewPip_ExecutableOverrideBypassesDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const override = "/nonexistent/pip"
	pip, err := NewPip(ctx, "pip", override)
	if err != nil {
		t.Fatalf("NewPip(%q) failed: %v", override, err)
	}
	if pip.Executable() != override {
		t.Fatalf("Executable() = %q, want %q", pip.Executable(), override)
	}
}

func TestResolveInstallTargets_DryRunGating(t *testing.T) {
	pip := requireSystemPip(t)

	// --ignore-installed forces pip to treat testTarget as an install target
	// even if it happens to already be installed in the ambient test
	// environment, keeping these assertions independent of local state.
	tests := []struct {
		name       string
		command    []string
		hasTargets bool
	}{
		{name: "plain install", command: []string{"install", "--ignore-installed", testTarget}, hasTargets: true},
		{name: "-h before install", command: []string{"-h", "install", testTarget}, hasTargets: false},
		{name: "--help before install", command: []string{"--help", "install", testTarget}, hasTargets: false},
		{name: "-h after install", command: []string{"install", "-h", testTarget}, hasTargets: false},
		{name: "--help after install", command: []string{"install", "--help", testTarget}, hasTargets: false},
		{name: "--dry-run after install", command: []string{"install", "--dry-run", testTarget}, hasTargets: false},
		{name: "--dry-run before install", command: []string{"--dry-run", "install", testTarget}, hasTargets: false},
		{name: "explicit --report is overridden", command: []string{"install", "--ignore-installed", "--report", "report.json", testTarget}, hasTargets: true},
		{name: "non-existent option", command: []string{"install", "--non-existent-option", testTarget}, hasTargets: false},
		{name: "-v", command: []string{"install", "--ignore-installed", "-v", testTarget}, hasTargets: true},
		{name: "-vv", command: []string{"install", "--ignore-installed", "-vv", testTarget}, hasTargets: true},
		{name: "-vvv", command: []string{"install", "--ignore-installed", "-vvv", testTarget}, hasTargets: true},
		{name: "-vvvv", command: []string{"install", "--ignore-installed", "-vvvv", testTarget}, hasTargets: true},
		{name: "--verbose x1", command: []string{"install", "--ignore-installed", "--verbose", testTarget}, hasTargets: true},
		{name: "--verbose x2", command: []string{"install", "--ignore-installed", "--verbose", "--verbose", testTarget}, hasTargets: true},
		{name: "--verbose x3", command: []string{"install", "--ignore-installed", "--verbose", "--verbose", "--verbose", testTarget}, hasTargets: true},
		{name: "--verbose x4", command: []string{"install", "--ignore-installed", "--verbose", "--verbose", "--verbose", "--verbose", testTarget}, hasTargets: true},
		{name: "non-install command is not gated", command: []string{"list"}, hasTargets: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			targets, err := pip.ResolveInstallTargets(ctx, tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) returned unexpected error: %v", tc.command, err)
			}

			if got := targets.Len() > 0; got != tc.hasTargets {
				t.Fatalf("ResolveInstallTargets(%v) has targets = %v, want %v", tc.command, got, tc.hasTargets)
			}

			if !tc.hasTargets {
				return
			}
			if !targets.Contains(testTargetPackage) {
				t.Errorf("ResolveInstallTargets(%v) = %v, want it to contain %+v", tc.command, targets, testTargetPackage)
			}
		})
	}
}

func TestResolvePipVersion_RealPip(t *testing.T) {
	pip := requireSystemPip(t)

	if pip.versionErr != nil {
		t.Fatalf("failed to resolve version of real pip executable %q: %v", pip.Executable(), pip.versionErr)
	}
	if pip.version.Major == 0 && pip.version.Minor == 0 && pip.version.Patch == 0 {
		t.Fatalf("resolved a suspicious zero version for real pip executable %q", pip.Executable())
	}
}

func TestParsePipInstallReportEntry(t *testing.T) {
	tests := []struct {
		name    string
		entry   pipInstallReportEntry
		wantErr bool
		want    pm.Package
	}{
		{
			name: "single target",
			entry: pipInstallReportEntry{
				Metadata: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{Name: "six", Version: "1.16.0"},
				DownloadInfo: struct {
					URL string `json:"url"`
				}{URL: "https://files.pythonhosted.org/packages/six-1.16.0.whl"},
			},
			want: pm.Package{
				Ecosystem: ecosystem.PYPI,
				Name:      "six",
				Version:   "1.16.0",
				Source:    "https://files.pythonhosted.org/packages/six-1.16.0.whl",
			},
		},
		{
			name: "missing name",
			entry: pipInstallReportEntry{
				Metadata: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{Version: "1.16.0"},
			},
			wantErr: true,
		},
		{
			name: "missing version",
			entry: pipInstallReportEntry{
				Metadata: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{Name: "six"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePipInstallReportEntry(tc.entry)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePipInstallReportEntry(%+v) = %v, want error", tc.entry, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePipInstallReportEntry(%+v) returned unexpected error: %v", tc.entry, err)
			}
			if got != tc.want {
				t.Fatalf("parsePipInstallReportEntry(%+v) = %+v, want %+v", tc.entry, got, tc.want)
			}
		})
	}
}
