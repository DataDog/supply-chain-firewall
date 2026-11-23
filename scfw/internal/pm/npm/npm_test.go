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
	"strings"
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
	if os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") != "" {
		return runNpmGlobalFixture(args)
	}
	if os.Getenv("SCFW_TEST_NPM_PREFIX_PROJECT") != "" {
		return runNpmPrefixFixture(args)
	}
	if selected := os.Getenv("SCFW_TEST_NPM_SELECTION_CASE"); selected != "" {
		return runNpmSelectionFixture(fixtureDir, selected, args)
	}
	if len(args) > 0 && args[0] == "config" {
		fmt.Println(`{"global":false}`)
		return 0
	}
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
	// A global dry run would not touch the temporary project, so SCFW must
	// have turned it into a local one.
	if slices.Contains(args, "--dry-run") && slices.Contains(parseNpmOptions(args), npmOption{"global", "true"}) {
		return 1
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

func TestNewNpmDetectsNpx(t *testing.T) {
	fixtureNpm(t)
	for name, want := range map[string]bool{"npx": true, "/usr/local/bin/npx": true, "npm": false} {
		manager, err := NewNpm(context.Background(), name, os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		if manager.npx != want {
			t.Fatalf("NewNpm(%q).npx = %v, want %v", name, manager.npx, want)
		}
	}
	if !slices.Contains(NpmExecutableNames, "npx") {
		t.Fatalf("NpmExecutableNames = %q, want npx included", NpmExecutableNames)
	}
}

// Without the proxy nothing would evaluate what npx runs, so it must not run.
func TestNpxRequiresProxyMode(t *testing.T) {
	manager := fixtureNpm(t)
	manager.npx = true
	chdirT(t, fixtureNpmProject(t))
	targets, err := manager.ResolveInstallTargets(context.Background(), []string{"cowsay"})
	if err == nil || !strings.Contains(err.Error(), "SCFW_PROXY_ENABLED=1") {
		t.Fatalf("ResolveInstallTargets() = %v, %v, want a proxy mode error", targets, err)
	}
}

func TestNpmResolveInstallTargets_GatingWithLocalFixture(t *testing.T) {
	npm := fixtureNpm(t)
	chdirT(t, fixtureNpmProject(t))

	tests := []struct {
		name       string
		command    []string
		hasTargets bool
		refuses    string // the command expected in the proxy mode refusal
	}{
		{name: "install", command: []string{"install", "react@18.3.0"}, hasTargets: true},
		{name: "install after a flag", command: []string{"--silent", "install", "react@18.3.0"}, hasTargets: true},
		{name: "install after an option with a value", command: []string{"--prefix", "web", "install", "react@18.3.0"}, hasTargets: true},
		{name: "install after a separator", command: []string{"--", "install", "react@18.3.0"}, hasTargets: true},
		{name: "install alias", command: []string{"add", "react@18.3.0"}, hasTargets: true},
		{name: "global install", command: []string{"install", "--global", "react@18.3.0"}, hasTargets: true},
		{name: "global install shorthand group", command: []string{"install", "-gD", "react@18.3.0"}, hasTargets: true},
		{name: "global install assigned shorthand", command: []string{"install", "-g=true", "react@18.3.0"}, hasTargets: true},
		{name: "help", command: []string{"install", "--help", "react@18.3.0"}},
		{name: "already dry run", command: []string{"install", "--dry-run", "react@18.3.0"}},
		{name: "version", command: []string{"install", "--version"}},
		{name: "other command", command: []string{"list"}},
		{name: "script named like an install alias", command: []string{"run", "add"}},
		{name: "audit without fix", command: []string{"audit"}},
		{name: "init without an initializer", command: []string{"init", "-y"}},
		{name: "fetching command with --dry-run", command: []string{"ci", "--dry-run"}},
		{name: "fetching command with --help", command: []string{"ci", "--help"}},
		// Best effort: an abbreviation is not recognized.
		{name: "abbreviated update", command: []string{"upd"}},
		{name: "ci", command: []string{"ci"}, refuses: "ci"},
		{name: "clean-install", command: []string{"clean-install"}, refuses: "ci"},
		{name: "update", command: []string{"update"}, refuses: "update"},
		{name: "up", command: []string{"up", "x"}, refuses: "update"},
		{name: "ci after flags", command: []string{"--silent", "-g", "ci"}, refuses: "ci"},
		{name: "ci after an option with a value", command: []string{"--prefix", "web", "ci"}, refuses: "ci"},
		{name: "ci after a color value", command: []string{"--color", "always", "ci"}, refuses: "ci"},
		{name: "ci after a separator", command: []string{"--", "ci"}, refuses: "ci"},
		{name: "ci after an option value and a separator", command: []string{"-C", "web", "--", "ci"}, refuses: "ci"},
		{name: "init initializer after a separator", command: []string{"init", "--", "vite"}, refuses: "init"},
		{name: "audit fix after a separator", command: []string{"audit", "--", "fix"}, refuses: "audit"},
		// An option value named like a command is refused rather than guessed past.
		{name: "option value named like a command", command: []string{"--prefix", "x", "install", "react@18.3.0"}, refuses: "exec"},
		{name: "exec", command: []string{"exec", "cowsay"}, refuses: "exec"},
		{name: "x", command: []string{"x", "cowsay"}, refuses: "exec"},
		{name: "uninstall", command: []string{"rm", "x"}, refuses: "uninstall"},
		{name: "link", command: []string{"link"}, refuses: "link"},
		{name: "prune", command: []string{"prune"}, refuses: "prune"},
		{name: "cache add", command: []string{"cache", "add", "x"}, refuses: "cache"},
		{name: "audit fix", command: []string{"audit", "fix"}, refuses: "audit"},
		{name: "init with an initializer", command: []string{"init", "react-app"}, refuses: "init"},
		{name: "create", command: []string{"create", "vite"}, refuses: "init"},
		{name: "help flag of the executed tool", command: []string{"exec", "--", "tsc", "--help"}, refuses: "exec"},
		{name: "version flag of the executed tool", command: []string{"exec", "--", "cowsay", "--version"}, refuses: "exec"},
		{name: "dry-run after the separator", command: []string{"ci", "--", "--dry-run"}, refuses: "ci"},
		{name: "dry-run set to false", command: []string{"ci", "--dry-run", "false"}, refuses: "ci"},
		{name: "dry-run assigned false", command: []string{"ci", "--dry-run=false"}, refuses: "ci"},
		{name: "install dry-run set to false", command: []string{"install", "--dry-run", "false", "react@18.3.0"}, hasTargets: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := npm.ResolveInstallTargets(context.Background(), tc.command)
			if tc.refuses != "" {
				if err == nil || !strings.Contains(err.Error(), "npm "+tc.refuses+" requires proxy mode") ||
					!strings.Contains(err.Error(), "SCFW_PROXY_ENABLED=1") {
					t.Fatalf("ResolveInstallTargets(%v) = %v, want the %s proxy mode refusal", tc.command, err, tc.refuses)
				}
				return
			}
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
