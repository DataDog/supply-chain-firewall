// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

const fakePipFixtureDirEnv = "SCFW_TEST_FAKE_PIP_FIXTURE_DIR"

var sixPublishDate = time.Date(2021, 5, 5, 14, 18, 18, 379524000, time.UTC)

func TestMain(m *testing.M) {
	fixtureDir := os.Getenv(fakePipFixtureDirEnv)
	if fixtureDir != "" {
		os.Exit(runFakePip(fixtureDir, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runFakePip(fixtureDir string, args []string) int {
	if slices.Contains(args, "--version") {
		fmt.Println("pip 24.0 from /local/fixture/pip (python 3.12)")
		return 0
	}
	if slices.Contains(args, "missing==1.0") || slices.Contains(args, "--non-existent-option") {
		fmt.Fprintln(os.Stderr, "no matching distribution")
		return 1
	}
	report, err := os.ReadFile(filepath.Join(fixtureDir, "six-report.json"))
	if err != nil {
		return 1
	}
	_, _ = os.Stdout.Write(report)
	return 0
}

func fixturePip(t *testing.T) Pip {
	t.Helper()
	fixtureDir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("filepath.Abs(testdata) failed: %v", err)
	}
	t.Setenv(fakePipFixtureDirEnv, fixtureDir)
	return Pip{
		executable: os.Args[0],
		version:    minPipVersion,
		resolvePublishDate: func(_ context.Context, _ ecosystem.Ecosystem, name, version, _ string) (time.Time, error) {
			if name != "six" || version != "1.16.0" {
				return time.Time{}, fmt.Errorf("no publish-date fixture for %s@%s", name, version)
			}
			return sixPublishDate, nil
		},
	}
}

func TestPipCheckVersion(t *testing.T) {
	tests := []struct {
		name string
		pip  Pip
		want bool
	}{
		{name: "supported", pip: Pip{version: minPipVersion}},
		{name: "too old", pip: Pip{version: pm.Version{Major: minPipVersion.Major - 1}}, want: true},
		{name: "unresolved", pip: Pip{versionErr: errors.New("boom")}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.pip.checkVersion()
			if got := errors.Is(err, pm.ErrUnsupportedVersion); got != tc.want {
				t.Fatalf("checkVersion() error = %v, wraps ErrUnsupportedVersion = %v, want %v", err, got, tc.want)
			}
		})
	}
}

func TestNewPip_LocalExecutableFixture(t *testing.T) {
	fixturePip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pip, err := NewPip(ctx, "pip", os.Args[0])
	if err != nil {
		t.Fatalf("NewPip() failed: %v", err)
	}
	if pip.version != (pm.Version{Major: 24}) {
		t.Fatalf("NewPip() version = %v, want 24.0.0", pip.version)
	}
}

func TestResolveInstallTargets_UsesLocalReportFixture(t *testing.T) {
	pip := fixturePip(t)
	targets, err := pip.ResolveInstallTargets(context.Background(), []string{"install", "--ignore-installed", "six==1.16.0"})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}

	want := pm.Package{
		Ecosystem:   ecosystem.PYPI,
		Name:        "six",
		Version:     "1.16.0",
		Source:      "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl",
		PublishDate: sixPublishDate,
	}
	if targets.Len() != 1 || !targets.Contains(want) {
		t.Fatalf("ResolveInstallTargets() = %v, want {%+v}", targets, want)
	}
}

func TestResolveInstallTargets_GatingWithLocalFixture(t *testing.T) {
	pip := fixturePip(t)
	tests := []struct {
		name       string
		command    []string
		hasTargets bool
	}{
		{name: "install", command: []string{"install", "six==1.16.0"}, hasTargets: true},
		{name: "verbose install", command: []string{"install", "-vvv", "six==1.16.0"}, hasTargets: true},
		{name: "help", command: []string{"install", "--help", "six==1.16.0"}},
		{name: "already dry run", command: []string{"install", "--dry-run", "six==1.16.0"}},
		{name: "other command", command: []string{"list"}},
		{name: "invalid option", command: []string{"install", "--non-existent-option", "six==1.16.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := pip.ResolveInstallTargets(context.Background(), tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) failed: %v", tc.command, err)
			}
			if got := targets.Len() > 0; got != tc.hasTargets {
				t.Fatalf("ResolveInstallTargets(%v) has targets = %v, want %v", tc.command, got, tc.hasTargets)
			}
		})
	}
}

func TestResolveInstallTargets_DryRunFailureLogsOnlyAtDebug(t *testing.T) {
	pip := fixturePip(t)
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var warningOutput bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&warningOutput, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if _, err := pip.ResolveInstallTargets(context.Background(), []string{"install", "missing==1.0"}); err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}
	if warningOutput.Len() != 0 {
		t.Fatalf("warning output = %q, want none", warningOutput.String())
	}

	var debugOutput bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&debugOutput, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if _, err := pip.ResolveInstallTargets(context.Background(), []string{"install", "missing==1.0"}); err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}
	for _, want := range []string{"pip dry-run install failed", "no matching distribution"} {
		if !strings.Contains(debugOutput.String(), want) {
			t.Errorf("debug output %q does not contain %q", debugOutput.String(), want)
		}
	}
}

func TestParsePipInstallReportEntry(t *testing.T) {
	valid := pipInstallReportEntry{}
	valid.Metadata.Name = "six"
	valid.Metadata.Version = "1.16.0"
	valid.DownloadInfo.URL = "https://files.pythonhosted.org/packages/six-1.16.0.whl"

	got, err := parsePipInstallReportEntry(valid)
	if err != nil {
		t.Fatalf("parsePipInstallReportEntry() failed: %v", err)
	}
	want := pm.Package{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.16.0", Source: valid.DownloadInfo.URL}
	if got != want {
		t.Fatalf("parsePipInstallReportEntry() = %+v, want %+v", got, want)
	}

	missingName := valid
	missingName.Metadata.Name = ""
	if _, err := parsePipInstallReportEntry(missingName); err == nil {
		t.Fatal("parsePipInstallReportEntry() succeeded without a name")
	}
	missingVersion := valid
	missingVersion.Metadata.Version = ""
	if _, err := parsePipInstallReportEntry(missingVersion); err == nil {
		t.Fatal("parsePipInstallReportEntry() succeeded without a version")
	}
}
