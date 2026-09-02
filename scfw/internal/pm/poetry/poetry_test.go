// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

const fakePoetryFixtureDirEnv = "SCFW_TEST_FAKE_POETRY_FIXTURE_DIR"

var poetryFixturePublishDates = map[string]time.Time{
	"foo@0.1.0":  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	"idna@3.19":  time.Date(2026, 8, 18, 5, 14, 24, 270231000, time.UTC),
	"six@1.16.0": time.Date(2021, 5, 5, 14, 18, 18, 379524000, time.UTC),
}

func TestMain(m *testing.M) {
	fixtureDir := os.Getenv(fakePoetryFixtureDirEnv)
	if fixtureDir != "" {
		os.Exit(runFakePoetry(fixtureDir, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runFakePoetry(fixtureDir string, args []string) int {
	if slices.Contains(args, "--version") {
		fmt.Println("Poetry (version 2.1.3)")
		return 0
	}
	if slices.Contains(args, "!a_nonexistent_p@ckage_name") || slices.Contains(args, "--nonexistent-option") {
		return 1
	}
	if slices.Contains(args, "--dry-run") {
		output, err := os.ReadFile(filepath.Join(fixtureDir, "install-dry-run.txt"))
		if err != nil {
			return 1
		}
		_, _ = os.Stdout.Write(output)
		return 0
	}
	if slices.Contains(args, "lock") || slices.Contains(args, "--lock") {
		lockfile, err := os.ReadFile(filepath.Join(fixtureDir, "poetry-updated.lock"))
		if err != nil {
			return 1
		}
		if err := os.WriteFile("poetry.lock", lockfile, 0o644); err != nil {
			return 1
		}
	}
	return 0
}

func fixturePoetry(t *testing.T) Poetry {
	t.Helper()
	fixtureDir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("filepath.Abs(testdata) failed: %v", err)
	}
	t.Setenv(fakePoetryFixtureDirEnv, fixtureDir)
	return Poetry{
		executable: os.Args[0],
		version:    pm.Version{Major: 2, Minor: 1, Patch: 3},
		resolvePublishDate: func(_ context.Context, _ ecosystem.Ecosystem, name, version, _ string) (time.Time, error) {
			published, ok := poetryFixturePublishDates[name+"@"+version]
			if !ok {
				return time.Time{}, fmt.Errorf("no publish-date fixture for %s@%s", name, version)
			}
			return published, nil
		},
	}
}

func copyPoetryFixture(t *testing.T, name, destination string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		t.Fatalf("failed to write fixture %s: %v", destination, err)
	}
}

func fixturePoetryProject(t *testing.T, lockFixture string) string {
	t.Helper()
	dir := t.TempDir()
	copyPoetryFixture(t, "pyproject.toml", filepath.Join(dir, "pyproject.toml"))
	if lockFixture != "" {
		copyPoetryFixture(t, lockFixture, filepath.Join(dir, "poetry.lock"))
	}
	return dir
}

func TestPoetryCheckVersion(t *testing.T) {
	tests := []struct {
		name   string
		poetry Poetry
		want   bool
	}{
		{name: "supported", poetry: Poetry{version: minPoetryVersion}},
		{name: "too old", poetry: Poetry{version: pm.Version{Major: 1, Minor: 6}}, want: true},
		{name: "unresolved", poetry: Poetry{versionErr: errors.New("boom")}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.poetry.checkVersion()
			if got := errors.Is(err, pm.ErrUnsupportedVersion); got != tc.want {
				t.Fatalf("checkVersion() error = %v, wraps ErrUnsupportedVersion = %v, want %v", err, got, tc.want)
			}
		})
	}
}

func TestNewPoetry_LocalExecutableFixture(t *testing.T) {
	fixturePoetry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	poetry, err := NewPoetry(ctx, "poetry", os.Args[0])
	if err != nil {
		t.Fatalf("NewPoetry() failed: %v", err)
	}
	if poetry.version != (pm.Version{Major: 2, Minor: 1, Patch: 3}) {
		t.Fatalf("NewPoetry() version = %v, want 2.1.3", poetry.version)
	}
}

func TestPoetryResolveInstallTargets_DryRunFixture(t *testing.T) {
	poetry := fixturePoetry(t)
	project := fixturePoetryProject(t, "poetry-updated.lock")

	targets, err := poetry.ResolveInstallTargets(context.Background(), []string{"install", "--directory", project})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}
	want := []pm.Package{
		{Ecosystem: ecosystem.PYPI, Name: "foo", Version: "0.1.0", PublishDate: poetryFixturePublishDates["foo@0.1.0"]},
		{Ecosystem: ecosystem.PYPI, Name: "idna", Version: "3.19", Source: "https://pypi.org/project/idna/3.19/", PublishDate: poetryFixturePublishDates["idna@3.19"]},
		{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.16.0", Source: "https://pypi.org/project/six/1.16.0/", PublishDate: poetryFixturePublishDates["six@1.16.0"]},
	}
	if targets.Len() != len(want) {
		t.Fatalf("ResolveInstallTargets() = %v, want %d targets", targets, len(want))
	}
	for _, pkg := range want {
		if !targets.Contains(pkg) {
			t.Errorf("ResolveInstallTargets() missing %+v; got %v", pkg, targets)
		}
	}
}

func TestPoetryResolveInstallTargets_LockRegenerationFixture(t *testing.T) {
	poetry := fixturePoetry(t)
	project := fixturePoetryProject(t, "poetry-current.lock")
	before, err := os.ReadFile(filepath.Join(project, "poetry.lock"))
	if err != nil {
		t.Fatalf("failed to read initial lock fixture: %v", err)
	}

	targets, err := poetry.ResolveInstallTargets(context.Background(), []string{
		"add", "--directory", project, "idna==3.19", "six==1.16.0",
	})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}
	want := []pm.Package{
		{Ecosystem: ecosystem.PYPI, Name: "idna", Version: "3.19", Source: "https://pypi.org/project/idna/3.19/", PublishDate: poetryFixturePublishDates["idna@3.19"]},
		{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.16.0", Source: "https://pypi.org/project/six/1.16.0/", PublishDate: poetryFixturePublishDates["six@1.16.0"]},
	}
	if targets.Len() != len(want) {
		t.Fatalf("ResolveInstallTargets() = %v, want %d targets", targets, len(want))
	}
	for _, pkg := range want {
		if !targets.Contains(pkg) {
			t.Errorf("ResolveInstallTargets() missing %+v; got %v", pkg, targets)
		}
	}
	after, err := os.ReadFile(filepath.Join(project, "poetry.lock"))
	if err != nil {
		t.Fatalf("failed to read lock fixture after resolution: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("ResolveInstallTargets() modified the fixture project's poetry.lock")
	}
}

func TestGetPoetrySourceMap_GeneratesLocalLockFixture(t *testing.T) {
	poetry := fixturePoetry(t)
	project := fixturePoetryProject(t, "")

	sources := getPoetrySourceMap(context.Background(), poetry.Executable(), []string{"install", "--directory", project})
	for _, key := range []poetryPackageKey{{name: "idna", version: "3.19"}, {name: "six", version: "1.16.0"}} {
		if sources[key] == "" {
			t.Errorf("getPoetrySourceMap() has no source for %+v: %v", key, sources)
		}
	}
	if _, err := os.Stat(filepath.Join(project, "poetry.lock")); !os.IsNotExist(err) {
		t.Fatalf("getPoetrySourceMap() modified the fixture project: poetry.lock stat error = %v", err)
	}
}

func TestPoetryResolveInstallTargets_GatingWithLocalFixture(t *testing.T) {
	poetry := fixturePoetry(t)
	project := fixturePoetryProject(t, "poetry-updated.lock")
	tests := []struct {
		name       string
		command    []string
		hasTargets bool
	}{
		{name: "install", command: []string{"install", "--directory", project}, hasTargets: true},
		{name: "help", command: []string{"install", "--help", "--directory", project}},
		{name: "already dry run", command: []string{"install", "--dry-run", "--directory", project}},
		{name: "version", command: []string{"--version", "install", "--directory", project}},
		{name: "other command", command: []string{"show", "--directory", project}},
		{name: "empty command", command: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := poetry.ResolveInstallTargets(context.Background(), tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) failed: %v", tc.command, err)
			}
			if got := targets.Len() > 0; got != tc.hasTargets {
				t.Fatalf("ResolveInstallTargets(%v) has targets = %v, want %v", tc.command, got, tc.hasTargets)
			}
		})
	}
}

func TestPoetryResolveInstallTargets_LocalFixtureErrors(t *testing.T) {
	poetry := fixturePoetry(t)
	project := fixturePoetryProject(t, "poetry-current.lock")
	tests := [][]string{
		{"add", "--directory", project, "!a_nonexistent_p@ckage_name"},
		{"install", "--directory", project, "--nonexistent-option"},
	}
	for _, command := range tests {
		targets, err := poetry.ResolveInstallTargets(context.Background(), command)
		if err != nil {
			t.Fatalf("ResolveInstallTargets(%v) failed: %v", command, err)
		}
		if targets.Len() != 0 {
			t.Errorf("ResolveInstallTargets(%v) = %v, want no targets", command, targets)
		}
	}
}

func TestParsePoetryDryRunLine(t *testing.T) {
	tests := []struct {
		line   string
		want   pm.Package
		wantOK bool
	}{
		{line: "Installing idna (3.19)", want: pm.Package{Ecosystem: ecosystem.PYPI, Name: "idna", Version: "3.19"}, wantOK: true},
		{line: "Updating idna (3.18 -> 3.19)", want: pm.Package{Ecosystem: ecosystem.PYPI, Name: "idna", Version: "3.19"}, wantOK: true},
		{line: "Downgrading idna (3.19 -> 3.18)", want: pm.Package{Ecosystem: ecosystem.PYPI, Name: "idna", Version: "3.18"}, wantOK: true},
		{line: "Installing idna (3.19): Skipped", wantOK: false},
		{line: "Resolving dependencies", wantOK: false},
	}
	for _, tc := range tests {
		got, ok := parsePoetryDryRunLine(tc.line)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("parsePoetryDryRunLine(%q) = (%+v, %v), want (%+v, %v)", tc.line, got, ok, tc.want, tc.wantOK)
		}
	}
}
