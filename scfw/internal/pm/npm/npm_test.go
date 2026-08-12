// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// testNpmTarget is a small, stable, pinned npm package used as a dry-run
// install target. Pinning avoids resolution drift over time.
const testNpmTarget = "left-pad@1.3.0"

// testPackagePublishDates are the real npm publish dates of the packages
// used as test targets, confirmed against the npm registry, so that expected
// targets can be asserted by full equality rather than field by field.
var testPackagePublishDates = map[string]time.Time{
	"left-pad@1.3.0":     time.Date(2018, 4, 9, 1, 10, 45, 796000000, time.UTC),
	"react@18.3.0":       time.Date(2024, 4, 25, 16, 45, 54, 126000000, time.UTC),
	"react@18.2.0":       time.Date(2022, 6, 14, 19, 46, 38, 369000000, time.UTC),
	"js-tokens@4.0.0":    time.Date(2018, 1, 28, 11, 58, 58, 170000000, time.UTC),
	"loose-envify@1.4.0": time.Date(2018, 7, 10, 11, 9, 45, 917000000, time.UTC),
}

// requireSystemNpm locates a real npm executable in the test environment,
// skipping the test if none is available.
func requireSystemNpm(t *testing.T) Npm {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("no npm executable found in PATH")
	}
	npm, err := NewNpm(ctx, "npm", "")
	if err != nil {
		t.Fatalf("NewNpm(%q) failed: %v", "npm", err)
	}
	return npm
}

func TestNpmCheckVersion_TooOld(t *testing.T) {
	npm := Npm{version: pm.Version{Major: minNpmVersion.Major - 1}}
	err := npm.checkVersion()
	if !errors.Is(err, pm.ErrUnsupportedVersion) {
		t.Fatalf("checkVersion() = %v, want error wrapping ErrUnsupportedVersion", err)
	}
}

func TestNpmCheckVersion_UnresolvedVersion(t *testing.T) {
	npm := Npm{versionErr: errors.New("boom")}
	err := npm.checkVersion()
	if !errors.Is(err, pm.ErrUnsupportedVersion) {
		t.Fatalf("checkVersion() = %v, want error wrapping ErrUnsupportedVersion", err)
	}
}

func TestNpmCheckVersion_Supported(t *testing.T) {
	npm := Npm{version: minNpmVersion}
	if err := npm.checkVersion(); err != nil {
		t.Fatalf("checkVersion() returned unexpected error: %v", err)
	}
}

func TestNewNpm_ExecutableOverrideBypassesDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const override = "/nonexistent/npm"
	npm, err := NewNpm(ctx, "npm", override)
	if err != nil {
		t.Fatalf("NewNpm(%q) failed: %v", override, err)
	}
	if npm.Executable() != override {
		t.Fatalf("Executable() = %q, want %q", npm.Executable(), override)
	}
}

func TestResolveNpmVersion_RealNpm(t *testing.T) {
	npm := requireSystemNpm(t)

	if npm.versionErr != nil {
		t.Fatalf("failed to resolve version of real npm executable %q: %v", npm.Executable(), npm.versionErr)
	}
	if npm.version.Major == 0 && npm.version.Minor == 0 && npm.version.Patch == 0 {
		t.Fatalf("resolved a suspicious zero version for real npm executable %q", npm.Executable())
	}
}

func TestNpmResolveInstallTargets_DryRunGating(t *testing.T) {
	npm := requireSystemNpm(t)

	tests := []struct {
		name       string
		command    []string
		hasTargets bool
	}{
		{name: "plain install", command: []string{"install", testNpmTarget}, hasTargets: true},
		{name: "install alias", command: []string{"add", testNpmTarget}, hasTargets: true},
		{name: "-g install still resolves targets", command: []string{"install", "-g", testNpmTarget}, hasTargets: true},
		{name: "--global install still resolves targets", command: []string{"install", "--global", testNpmTarget}, hasTargets: true},
		{name: "-g before install", command: []string{"-g", "install", testNpmTarget}, hasTargets: true},
		{name: "-h before install", command: []string{"-h", "install", testNpmTarget}, hasTargets: false},
		{name: "--help before install", command: []string{"--help", "install", testNpmTarget}, hasTargets: false},
		{name: "-h after install", command: []string{"install", "-h", testNpmTarget}, hasTargets: false},
		{name: "--help after install", command: []string{"install", "--help", testNpmTarget}, hasTargets: false},
		{name: "--dry-run after install", command: []string{"install", "--dry-run", testNpmTarget}, hasTargets: false},
		{name: "--dry-run before install", command: []string{"--dry-run", "install", testNpmTarget}, hasTargets: false},
		{name: "--version", command: []string{"install", "--version"}, hasTargets: false},
		{name: "non-install command is not gated", command: []string{"list"}, hasTargets: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			targets, err := npm.ResolveInstallTargets(ctx, tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) returned unexpected error: %v", tc.command, err)
			}

			if got := targets.Len() > 0; got != tc.hasTargets {
				t.Fatalf("ResolveInstallTargets(%v) has targets = %v, want %v", tc.command, got, tc.hasTargets)
			}
		})
	}
}

func TestNpmResolveInstallTargets_RealInstall(t *testing.T) {
	npm := requireSystemNpm(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	targets, err := npm.ResolveInstallTargets(ctx, []string{"install", testNpmTarget})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() returned unexpected error: %v", err)
	}

	want := buildRegistryPackage("left-pad", "1.3.0")
	if !targets.Contains(want) {
		t.Fatalf("ResolveInstallTargets() missing expected target %+v", want)
	}
}

// Tests establishing the validity of this package's assumptions about npm's
// command-line options and behavior, mirroring the Python reference
// implementation's tests/package_managers/test_npm.py.

// getSillyLogLines runs the given npm command in dir and returns the `sill`
// (or `silly`, depending on npm version) log lines from its stderr output,
// asserting they all share the expected `npm sill(y) <line>` format.
func getSillyLogLines(t *testing.T, npm Npm, dir string, args ...string) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, npm.Executable(), args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("npm %v failed: %v\n%s", args, err, stderr.String())
	}

	var sillyLines []string
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		if strings.HasPrefix(line, "npm sill") {
			sillyLines = append(sillyLines, line)
		}
	}

	sillTag, sillyTag := 0, 0
	for _, line := range sillyLines {
		switch strings.Fields(line)[1] {
		case "sill":
			sillTag++
		case "silly":
			sillyTag++
		}
	}
	if sillTag > 0 && sillyTag > 0 {
		t.Fatalf("silly log lines mix \"sill\" and \"silly\" tags: %v", sillyLines)
	}

	return sillyLines
}

func TestNpmPrefix_EmptyDirectory(t *testing.T) {
	npm := requireSystemNpm(t)
	dir := t.TempDir()

	output := runNpmCommand(t, npm, dir, "prefix")
	prefix := strings.TrimSpace(string(output))

	if resolvedAbs(t, prefix) != resolvedAbs(t, dir) {
		t.Fatalf("npm prefix = %q, want %q", prefix, dir)
	}
	if _, err := exec.LookPath(prefix); err == nil {
		t.Fatalf("npm prefix %q unexpectedly resolved as an executable", prefix)
	}
}

func TestNpmLoglevelOverride(t *testing.T) {
	npm := requireSystemNpm(t)
	dir := t.TempDir()

	// npm honors only the last --loglevel flag it's given; this is what lets
	// ResolveInstallTargets force verbose logging regardless of any --loglevel
	// the caller's command already contains.
	lines := getSillyLogLines(
		t, npm, dir,
		"--loglevel", "silent", "install", "--dry-run", testPackage, "--loglevel", "silly",
	)
	if len(lines) == 0 {
		t.Fatal("expected silly log lines after overriding --loglevel silent with a trailing --loglevel silly, got none")
	}
}

func TestNpmLogLineFormat_PlaceDepAndAdd(t *testing.T) {
	npm := requireSystemNpm(t)
	dir := t.TempDir()

	lines := getSillyLogLines(t, npm, dir, "install", testPackageLatestSpec, "--dry-run", "--loglevel", "silly")
	if len(lines) == 0 {
		t.Fatal("expected silly log lines, got none")
	}

	var placeDepLines, addLines []string
	for _, line := range lines {
		switch {
		case strings.Contains(line, "placeDep"):
			placeDepLines = append(placeDepLines, line)
		case strings.Contains(line, "ADD"):
			addLines = append(addLines, line)
		}
	}

	if len(placeDepLines) == 0 {
		t.Fatal("expected placeDep log lines, got none")
	}
	foundTarget := false
	for _, line := range placeDepLines {
		tokens := strings.Fields(line)
		if tokens[2] != "placeDep" {
			t.Fatalf("placeDep line has unexpected format: %q", line)
		}
		if tokens[4] == testPackageLatestSpec {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Fatalf("expected a placeDep line for %q, got %v", testPackageLatestSpec, placeDepLines)
	}

	if len(addLines) == 0 {
		t.Fatal("expected ADD log lines, got none")
	}
	foundTarget = false
	for _, line := range addLines {
		tokens := strings.Fields(line)
		if tokens[2] != "ADD" || !strings.HasPrefix(tokens[3], "node_modules/") {
			t.Fatalf("ADD line has unexpected format: %q", line)
		}
		if tokens[3] == "node_modules/"+testPackage {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Fatalf("expected an ADD line for node_modules/%s, got %v", testPackage, addLines)
	}
}

func TestNpmLogLineFormat_Change(t *testing.T) {
	npm := requireSystemNpm(t)
	dir := t.TempDir()
	setupNpmProject(t, npm, dir, []string{testPackagePreviousSpec}, true, true)

	lines := getSillyLogLines(t, npm, dir, "install", testPackageLatestSpec, "--dry-run", "--loglevel", "silly")
	if len(lines) == 0 {
		t.Fatal("expected silly log lines, got none")
	}

	var changeLines []string
	for _, line := range lines {
		if strings.Contains(line, "CHANGE") {
			changeLines = append(changeLines, line)
		}
	}
	if len(changeLines) == 0 {
		t.Fatal("expected CHANGE log lines, got none")
	}

	foundTarget := false
	for _, line := range changeLines {
		tokens := strings.Fields(line)
		if tokens[2] != "CHANGE" || !strings.HasPrefix(tokens[3], "node_modules/") {
			t.Fatalf("CHANGE line has unexpected format: %q", line)
		}
		if tokens[3] == "node_modules/"+testPackage {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Fatalf("expected a CHANGE line for node_modules/%s, got %v", testPackage, changeLines)
	}
}

// Mirrors the fixtures used by the Python reference implementation's
// tests/package_managers/npm_fixtures.py, so that real npm end-to-end
// coverage tracks the same project states.
const (
	localPackageName    = "foo-local-test-package"
	localPackageVersion = "1.0.0"

	testPackage         = "react"
	testPackageLatest   = "18.3.0"
	testPackagePrevious = "18.2.0"
)

var (
	testPackageLatestSpec   = testPackage + "@" + testPackageLatest
	testPackagePreviousSpec = testPackage + "@" + testPackagePrevious
)

// testPackageLatestDependencies are the known dependencies of
// testPackage@testPackageLatest.
var testPackageLatestDependencies = []struct{ name, version string }{
	{testPackage, testPackageLatest},
	{"js-tokens", "4.0.0"},
	{"loose-envify", "1.4.0"},
}

func npmRegistryTarballURL(name, version string) string {
	return fmt.Sprintf("https://registry.npmjs.org/%[1]s/-/%[1]s-%[2]s.tgz", name, version)
}

func buildRegistryPackage(name, version string) pm.Package {
	publishDate, ok := testPackagePublishDates[name+"@"+version]
	if !ok {
		panic(fmt.Sprintf("no known publish date for test target %s@%s", name, version))
	}
	return pm.Package{Ecosystem: ecosystem.NPM, Name: name, Version: version, Source: npmRegistryTarballURL(name, version), PublishDate: publishDate}
}

func testPackageLatestInstallTargets() *pm.Set[pm.Package] {
	targets := pm.NewSet[pm.Package]()
	for _, d := range testPackageLatestDependencies {
		targets.Add(buildRegistryPackage(d.name, d.version))
	}
	return targets
}

// chdirT changes the test process's working directory to dir for the
// duration of the test. This is required (rather than just passing a Dir to
// individual subprocess calls) because ResolveInstallTargets ultimately
// shells out to `npm prefix` without an explicit working directory.
func chdirT(t *testing.T, dir string) {
	t.Helper()

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir(%q) failed: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatalf("failed to restore working directory to %q: %v", orig, err)
		}
	})
}

func runNpmCommand(t *testing.T, npm Npm, dir string, args ...string) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, npm.Executable(), args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("npm %v failed: %v\n%s", args, err, output)
	}
	return output
}

// newLocalPackageDir creates a minimal npm package in its own temporary
// directory, for use as a local (file:) dependency in other test projects.
func newLocalPackageDir(t *testing.T, name, version string) string {
	t.Helper()

	dir := t.TempDir()
	packageJSON := fmt.Sprintf(`{"name": %q, "version": %q}`, name, version)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0o644); err != nil {
		t.Fatalf("failed to write local package.json: %v", err)
	}
	return dir
}

// resolvedAbs returns the canonical absolute form of path, resolving any
// symlinked ancestors (e.g. macOS's /var -> /private/var). This must match
// how ResolveInstallTargets reports local dependency sources, since it
// resolves the npm project root via `npm prefix` and derives sources
// relative to that already-canonicalized path.
func resolvedAbs(t *testing.T, path string) string {
	t.Helper()

	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) failed: %v", path, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(%q) failed: %v", abs, err)
	}
	return resolved
}

// setupNpmProject initializes an npm project in dir, installs each of specs
// (which may be registry specs like "react@18.3.0", alias specs like
// "alias@npm:react@18.3.0", or local directory paths), and then adjusts the
// presence of package-lock.json/node_modules to match withLockfile and
// withNodeModules. Mirrors Python's init_npm_project.
func setupNpmProject(t *testing.T, npm Npm, dir string, specs []string, withLockfile, withNodeModules bool) {
	t.Helper()

	runNpmCommand(t, npm, dir, "init", "--yes")

	if len(specs) == 0 {
		return
	}

	for _, spec := range specs {
		runNpmCommand(t, npm, dir, "install", "--save-exact", spec)
	}

	if !(withLockfile && withNodeModules) {
		if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
			t.Fatalf("failed to remove node_modules: %v", err)
		}
	}
	if !withLockfile {
		if err := os.Remove(filepath.Join(dir, "package-lock.json")); err != nil {
			t.Fatalf("failed to remove package-lock.json: %v", err)
		}
	}
}

// projectState returns a string snapshot of a real npm project's installed
// dependency tree, for verifying that resolving install targets doesn't
// mutate the caller's actual project.
func projectState(t *testing.T, npm Npm, dir string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, npm.Executable(), "list", "--all")
	cmd.Dir = dir
	// `npm list` can exit non-zero (e.g. ELSPROBLEMS for an unmet dependency)
	// while still producing meaningful, comparable output on stdout. stderr is
	// deliberately excluded: it includes a timestamped debug-log path that
	// differs between calls even when the project itself hasn't changed.
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()
	return strings.TrimSpace(stdout.String())
}

// resolveTargetsAndCheckUnmodified chdirs into dir, resolves install targets
// for command, and fails the test if doing so changed dir's dependency tree.
func resolveTargetsAndCheckUnmodified(t *testing.T, npm Npm, dir string, command []string) *pm.Set[pm.Package] {
	t.Helper()

	chdirT(t, dir)
	before := projectState(t, npm, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	targets, err := npm.ResolveInstallTargets(ctx, command)
	if err != nil {
		t.Fatalf("ResolveInstallTargets(%v) returned unexpected error: %v", command, err)
	}

	after := projectState(t, npm, dir)
	if before != after {
		t.Fatalf("ResolveInstallTargets(%v) modified project state:\nbefore:\n%s\nafter:\n%s", command, before, after)
	}

	return targets
}

func TestNpmResolveInstallTargets_LocalDependencyNotInstalled(t *testing.T) {
	npm := requireSystemNpm(t)
	localPkgDir := newLocalPackageDir(t, localPackageName, localPackageVersion)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{localPkgDir}, false, false)

	targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})

	wantSource := resolvedAbs(t, localPkgDir)
	want := pm.Package{Ecosystem: ecosystem.NPM, Name: localPackageName, Version: localPackageVersion, Source: wantSource}
	if !targets.Contains(want) {
		t.Fatalf("ResolveInstallTargets() missing expected local dependency target %+v; got %v", want, targets)
	}
}

func TestNpmResolveInstallTargets_LocalDependencyLockfileOnly(t *testing.T) {
	npm := requireSystemNpm(t)
	localPkgDir := newLocalPackageDir(t, localPackageName, localPackageVersion)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{localPkgDir}, true, false)

	targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})

	wantSource := resolvedAbs(t, localPkgDir)
	want := pm.Package{Ecosystem: ecosystem.NPM, Name: localPackageName, Version: localPackageVersion, Source: wantSource}
	if !targets.Contains(want) {
		t.Fatalf("ResolveInstallTargets() missing expected local dependency target %+v; got %v", want, targets)
	}
}

func TestNpmResolveInstallTargets_LocalDependencyInstalled(t *testing.T) {
	npm := requireSystemNpm(t)
	localPkgDir := newLocalPackageDir(t, localPackageName, localPackageVersion)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{localPkgDir}, true, true)

	t.Run("reinstall reports no targets", func(t *testing.T) {
		targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})
		if targets.Len() != 0 {
			t.Fatalf("ResolveInstallTargets() = %v, want no targets", targets)
		}
	})

	t.Run("installing a new package doesn't re-report the local dependency", func(t *testing.T) {
		targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install", testPackageLatestSpec})
		want := testPackageLatestInstallTargets()
		if targets.Len() != want.Len() {
			t.Fatalf("ResolveInstallTargets() = %v, want %v", targets, want)
		}
		for pkg := range want.Items() {
			if !targets.Contains(pkg) {
				t.Fatalf("ResolveInstallTargets() missing expected target %+v; got %v", pkg, targets)
			}
		}
	})
}

// Regression test for a dangling node_modules symlink left behind when a
// local workspace package is deleted without updating the lockfile.
func TestNpmResolveInstallTargets_DanglingLocalDependencySymlink(t *testing.T) {
	npm := requireSystemNpm(t)
	localPkgDir := newLocalPackageDir(t, localPackageName, localPackageVersion)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{localPkgDir}, true, true)

	// npm may install file: dependencies as directory copies rather than
	// symlinks; force a relative symlink so the fixture reliably dangles
	// once the source directory is removed below.
	nodeModulesEntry := filepath.Join(projectDir, "node_modules", localPackageName)
	if err := os.RemoveAll(nodeModulesEntry); err != nil {
		t.Fatalf("failed to remove installed local dependency entry: %v", err)
	}
	relTarget, err := filepath.Rel(filepath.Dir(nodeModulesEntry), localPkgDir)
	if err != nil {
		t.Fatalf("failed to compute relative symlink target: %v", err)
	}
	if err := os.Symlink(relTarget, nodeModulesEntry); err != nil {
		t.Fatalf("failed to create dangling symlink: %v", err)
	}

	expectedSource := resolvedAbs(t, localPkgDir)

	if err := os.RemoveAll(localPkgDir); err != nil {
		t.Fatalf("failed to delete local package source: %v", err)
	}

	targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})

	want := pm.Package{Ecosystem: ecosystem.NPM, Name: localPackageName, Version: localPackageVersion, Source: expectedSource}
	if !targets.Contains(want) {
		t.Fatalf("ResolveInstallTargets() missing expected target %+v for dangling symlink; got %v", want, targets)
	}
}

func TestNpmResolveInstallTargets_AliasedDependency(t *testing.T) {
	npm := requireSystemNpm(t)
	aliasedSpec := fmt.Sprintf("test-alias@npm:%s", testPackageLatestSpec)

	tests := []struct {
		name         string
		withLockfile bool
	}{
		{name: "no lockfile", withLockfile: false},
		{name: "lockfile only", withLockfile: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := t.TempDir()
			setupNpmProject(t, npm, projectDir, []string{aliasedSpec}, tc.withLockfile, false)

			targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})

			want := testPackageLatestInstallTargets()
			if targets.Len() != want.Len() {
				t.Fatalf("ResolveInstallTargets() = %v, want %v", targets, want)
			}
			for pkg := range want.Items() {
				if !targets.Contains(pkg) {
					t.Fatalf("ResolveInstallTargets() missing expected target %+v (aliased dependency must resolve to its real name); got %v", pkg, targets)
				}
			}
		})
	}
}

func TestNpmResolveInstallTargets_TransitiveDependencies(t *testing.T) {
	npm := requireSystemNpm(t)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{testPackageLatestSpec}, false, false)

	targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})

	want := testPackageLatestInstallTargets()
	if targets.Len() != want.Len() {
		t.Fatalf("ResolveInstallTargets() = %v, want %v", targets, want)
	}
	for pkg := range want.Items() {
		if !targets.Contains(pkg) {
			t.Fatalf("ResolveInstallTargets() missing expected transitive target %+v; got %v", pkg, targets)
		}
	}
}

func TestNpmResolveInstallTargets_UpgradeInstalledDependency(t *testing.T) {
	npm := requireSystemNpm(t)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{testPackagePreviousSpec}, true, true)

	t.Run("reinstall reports no targets", func(t *testing.T) {
		targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})
		if targets.Len() != 0 {
			t.Fatalf("ResolveInstallTargets() = %v, want no targets", targets)
		}
	})

	t.Run("upgrading to latest reports only the upgraded package", func(t *testing.T) {
		targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install", testPackageLatestSpec})
		want := buildRegistryPackage(testPackage, testPackageLatest)
		if targets.Len() != 1 || !targets.Contains(want) {
			t.Fatalf("ResolveInstallTargets() = %v, want {%+v}", targets, want)
		}
	})
}

func TestNpmResolveInstallTargets_DowngradeInstalledDependency(t *testing.T) {
	npm := requireSystemNpm(t)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, []string{testPackageLatestSpec}, true, true)

	t.Run("reinstall reports no targets", func(t *testing.T) {
		targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install"})
		if targets.Len() != 0 {
			t.Fatalf("ResolveInstallTargets() = %v, want no targets", targets)
		}
	})

	t.Run("downgrading to previous reports only the downgraded package", func(t *testing.T) {
		targets := resolveTargetsAndCheckUnmodified(t, npm, projectDir, []string{"install", testPackagePreviousSpec})
		want := buildRegistryPackage(testPackage, testPackagePrevious)
		if targets.Len() != 1 || !targets.Contains(want) {
			t.Fatalf("ResolveInstallTargets() = %v, want {%+v}", targets, want)
		}
	})
}

func TestNpmResolveInstallTargets_NonexistentPackage(t *testing.T) {
	npm := requireSystemNpm(t)
	projectDir := t.TempDir()
	setupNpmProject(t, npm, projectDir, nil, false, false)

	targets := resolveTargetsAndCheckUnmodified(
		t, npm, projectDir,
		[]string{"install", "definitely-nonexistent-package-scfw-test-xyz@0.0.0-does-not-exist"},
	)
	if targets.Len() != 0 {
		t.Fatalf("ResolveInstallTargets() = %v, want no targets for a nonexistent package", targets)
	}
}

// TestNpmInstall_PackageLockOnlyIgnoreScripts pins down the assumption that
// resolveInstallCommandTargets' safe re-run of the install command relies on:
// `--package-lock-only` updates the lockfile without creating node_modules,
// and `--ignore-scripts` prevents lifecycle scripts from running.
func TestNpmInstall_PackageLockOnlyIgnoreScripts(t *testing.T) {
	npm := requireSystemNpm(t)
	dir := t.TempDir()
	setupNpmProject(t, npm, dir, nil, false, false)

	scriptMarker := "this-should-never-execute"
	packageJSONPath := filepath.Join(dir, "package.json")
	packageJSON, err := readNpmJSONFile(packageJSONPath)
	if err != nil {
		t.Fatalf("failed to read package.json: %v", err)
	}
	packageJSON["scripts"] = map[string]any{"preinstall": fmt.Sprintf("echo %q", scriptMarker)}
	if err := writeNpmJSONFile(packageJSONPath, packageJSON); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	output := runNpmCommand(t, npm, dir, "install", testPackageLatestSpec, "--package-lock-only", "--ignore-scripts")

	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err != nil {
		t.Fatalf("expected package-lock.json to be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("expected no node_modules to be created, got err = %v", err)
	}
	if strings.Contains(string(output), scriptMarker) {
		t.Fatalf("expected --ignore-scripts to prevent the preinstall script from running, got output: %s", output)
	}
}
