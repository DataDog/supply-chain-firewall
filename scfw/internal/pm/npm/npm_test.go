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
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

const fakeNpmFixtureDirEnv = "SCFW_TEST_FAKE_NPM_FIXTURE_DIR"

var npmFixturePublishDates = map[string]time.Time{
	"react@18.3.0":       time.Date(2024, 4, 25, 16, 45, 54, 126000000, time.UTC),
	"js-tokens@4.0.0":    time.Date(2018, 1, 28, 11, 58, 58, 170000000, time.UTC),
	"loose-envify@1.4.0": time.Date(2018, 7, 10, 11, 9, 45, 917000000, time.UTC),
}

func TestMain(m *testing.M) {
	fixtureDir := os.Getenv(fakeNpmFixtureDirEnv)
	if fixtureDir != "" {
		os.Exit(runFakeNpm(fixtureDir, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runFakeNpm(fixtureDir string, args []string) int {
	if slices.Contains(args, "--version") {
		fmt.Println("10.8.2")
		return 0
	}
	if len(args) == 1 && args[0] == "prefix" {
		cwd, err := os.Getwd()
		if err != nil {
			return 1
		}
		fmt.Println(cwd)
		return 0
	}
	if slices.Contains(args, "definitely-nonexistent-package-scfw-test-xyz@0.0.0-does-not-exist") {
		return 1
	}
	if slices.Contains(args, "--package-lock-only") {
		lockfile, err := os.ReadFile(filepath.Join(fixtureDir, "react-package-lock.json"))
		if err != nil {
			return 1
		}
		if err := os.WriteFile("package-lock.json", lockfile, 0o644); err != nil {
			return 1
		}
		return 0
	}

	log, err := os.ReadFile(filepath.Join(fixtureDir, "react-install.stderr"))
	if err != nil {
		return 1
	}
	_, _ = os.Stderr.Write(log)
	return 0
}

func fixtureNpm(t *testing.T) Npm {
	t.Helper()
	fixtureDir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("filepath.Abs(testdata) failed: %v", err)
	}
	t.Setenv(fakeNpmFixtureDirEnv, fixtureDir)
	return Npm{
		executable: os.Args[0],
		version:    minNpmVersion,
		resolvePublishDate: func(_ context.Context, _ ecosystem.Ecosystem, name, version, _ string) (time.Time, error) {
			published, ok := npmFixturePublishDates[name+"@"+version]
			if !ok {
				return time.Time{}, fmt.Errorf("no publish-date fixture for %s@%s", name, version)
			}
			return published, nil
		},
	}
}

func fixtureNpmProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	packageJSON := []byte(`{"name":"fixture-project","version":"1.0.0"}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), packageJSON, 0o644); err != nil {
		t.Fatalf("failed to write fixture package.json: %v", err)
	}
	return dir
}

func chdirT(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir(%q) failed: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Fatalf("failed to restore working directory to %q: %v", original, err)
		}
	})
}

func TestNpmCheckVersion(t *testing.T) {
	tests := []struct {
		name string
		npm  Npm
		want bool
	}{
		{name: "supported", npm: Npm{version: minNpmVersion}},
		{name: "too old", npm: Npm{version: pm.Version{Major: minNpmVersion.Major - 1}}, want: true},
		{name: "unresolved", npm: Npm{versionErr: errors.New("boom")}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.npm.checkVersion()
			if got := errors.Is(err, pm.ErrUnsupportedVersion); got != tc.want {
				t.Fatalf("checkVersion() error = %v, wraps ErrUnsupportedVersion = %v, want %v", err, got, tc.want)
			}
		})
	}
}

func TestNewNpm_LocalExecutableFixture(t *testing.T) {
	fixtureNpm(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	npm, err := NewNpm(ctx, "npm", os.Args[0])
	if err != nil {
		t.Fatalf("NewNpm() failed: %v", err)
	}
	if npm.version != (pm.Version{Major: 10, Minor: 8, Patch: 2}) {
		t.Fatalf("NewNpm() version = %v, want 10.8.2", npm.version)
	}
}

func TestNpmResolveInstallTargets_GatingWithLocalFixture(t *testing.T) {
	npm := fixtureNpm(t)
	chdirT(t, fixtureNpmProject(t))

	tests := []struct {
		name       string
		command    []string
		hasTargets bool
	}{
		{name: "install", command: []string{"install", "react@18.3.0"}, hasTargets: true},
		{name: "install alias", command: []string{"add", "react@18.3.0"}, hasTargets: true},
		{name: "global install", command: []string{"install", "--global", "react@18.3.0"}, hasTargets: true},
		{name: "help", command: []string{"install", "--help", "react@18.3.0"}},
		{name: "already dry run", command: []string{"install", "--dry-run", "react@18.3.0"}},
		{name: "version", command: []string{"install", "--version"}},
		{name: "other command", command: []string{"list"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := npm.ResolveInstallTargets(context.Background(), tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) failed: %v", tc.command, err)
			}
			if got := targets.Len() > 0; got != tc.hasTargets {
				t.Fatalf("ResolveInstallTargets(%v) has targets = %v, want %v", tc.command, got, tc.hasTargets)
			}
		})
	}
}

func TestNpmResolveInstallTargets_UsesLocalFixtures(t *testing.T) {
	npm := fixtureNpm(t)
	projectDir := fixtureNpmProject(t)
	chdirT(t, projectDir)

	targets, err := npm.ResolveInstallTargets(context.Background(), []string{"install", "react@18.3.0"})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}

	want := []pm.Package{
		{Ecosystem: ecosystem.NPM, Name: "react", Version: "18.3.0", Source: "https://registry.npmjs.org/react/-/react-18.3.0.tgz", PublishDate: npmFixturePublishDates["react@18.3.0"]},
		{Ecosystem: ecosystem.NPM, Name: "loose-envify", Version: "1.4.0", Source: "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz", PublishDate: npmFixturePublishDates["loose-envify@1.4.0"]},
		{Ecosystem: ecosystem.NPM, Name: "js-tokens", Version: "4.0.0", Source: "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz", PublishDate: npmFixturePublishDates["js-tokens@4.0.0"]},
	}
	if targets.Len() != len(want) {
		t.Fatalf("ResolveInstallTargets() = %v, want %d targets", targets, len(want))
	}
	for _, pkg := range want {
		if !targets.Contains(pkg) {
			t.Errorf("ResolveInstallTargets() missing %+v; got %v", pkg, targets)
		}
	}
	if _, err := os.Stat(filepath.Join(projectDir, "package-lock.json")); !os.IsNotExist(err) {
		t.Fatalf("ResolveInstallTargets() modified the fixture project: package-lock.json stat error = %v", err)
	}
}

func TestNpmResolveInstallTargets_LocalFixtureError(t *testing.T) {
	npm := fixtureNpm(t)
	chdirT(t, fixtureNpmProject(t))

	targets, err := npm.ResolveInstallTargets(context.Background(), []string{"install", "definitely-nonexistent-package-scfw-test-xyz@0.0.0-does-not-exist"})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() failed: %v", err)
	}
	if targets.Len() != 0 {
		t.Fatalf("ResolveInstallTargets() = %v, want no targets", targets)
	}
}
