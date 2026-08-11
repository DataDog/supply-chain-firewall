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
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/scfw/scfw/internal/ecosystem"
	"github.com/DataDog/scfw/scfw/internal/pm"
)

// Mirrors the fixtures and tests in the Python reference implementation's
// tests/package_managers/poetry_fixtures.py, test_poetry.py, and
// test_poetry_class.py.

const testPoetryProjectName = "foo"

// idna is a convenient test target because it never has any dependencies,
// is not part of the standard set of system Python modules, is pure Python
// (no native build step), and its GitHub tags need no submodule checkout.
const poetryTarget = "idna"

// Pinned idna versions used by the tests below. These are frozen rather than
// fetched from PyPI at collection time, to avoid flakiness from a new
// release appearing mid-run.
const (
	poetryTargetLatest   = "3.18"
	poetryTargetPrevious = "3.17"
)

var poetryTargetRepo = "https://github.com/kjd/idna"

// testPackagePublishDates are the real PyPI publish dates of the poetryTarget
// versions used as test targets, confirmed against the PyPI registry, so that
// expected targets can be asserted by full equality rather than field by field.
var testPackagePublishDates = map[string]time.Time{
	poetryTargetPrevious: time.Date(2026, 5, 28, 14, 32, 38, 550900000, time.UTC),
	poetryTargetLatest:   time.Date(2026, 6, 2, 14, 34, 7, 794523000, time.UTC),
}

// poetryTargetPackage returns the expected resolved pm.Package for poetryTarget
// at the given version, including its real PyPI source URL and publish date.
func poetryTargetPackage(version string) pm.Package {
	publishDate, ok := testPackagePublishDates[version]
	if !ok {
		panic(fmt.Sprintf("no known publish date for test target %s@%s", poetryTarget, version))
	}
	return pm.Package{
		Ecosystem:   ecosystem.PYPI,
		Name:        poetryTarget,
		Version:     version,
		Source:      fmt.Sprintf("%s/%s/%s/", pypiProjectBaseURL, poetryTarget, version),
		PublishDate: publishDate,
	}
}

var poetryV2 = pm.Version{Major: 2}

// requireSystemPoetry locates a real poetry executable in the test
// environment, skipping the test if none is available.
func requireSystemPoetry(t *testing.T) Poetry {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := exec.LookPath("poetry"); err != nil {
		t.Skip("no poetry executable found in PATH")
	}
	poetry, err := NewPoetry(ctx, "poetry", "")
	if err != nil {
		t.Fatalf("NewPoetry(%q) failed: %v", "poetry", err)
	}
	return poetry
}

func runPoetryCommand(t *testing.T, dir string, args ...string) ([]byte, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "poetry", args...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

func mustRunPoetryCommand(t *testing.T, dir string, args ...string) []byte {
	t.Helper()

	output, err := runPoetryCommand(t, dir, args...)
	if err != nil {
		t.Fatalf("poetry %v failed: %v\n%s", args, err, output)
	}
	return output
}

// initPoetryProject initializes a fresh Poetry project in dir, locks it, and
// installs each of deps at its pinned version. Mirrors Python's
// _init_poetry_project.
func initPoetryProject(t *testing.T, dir string, deps []struct{ name, version string }) {
	t.Helper()

	mustRunPoetryCommand(t, dir, "init", "--no-interaction", "--name", testPoetryProjectName)
	mustRunPoetryCommand(t, dir, "lock")

	venvPath := filepath.Join(dir, "venv")
	pythonPath := "python3"
	venvCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := exec.CommandContext(venvCtx, pythonPath, "-m", "venv", venvPath).Run(); err != nil {
		t.Fatalf("failed to create venv: %v", err)
	}
	venvPython := filepath.Join(venvPath, "bin", "python")
	if runtime.GOOS == "windows" {
		venvPython = filepath.Join(venvPath, "Scripts", "python.exe")
	}
	mustRunPoetryCommand(t, dir, "env", "use", venvPython)
	t.Cleanup(func() {
		// poetry never cleans up its global virtualenv cache on its own.
		if _, err := runPoetryCommand(t, dir, "env", "remove", "--all"); err != nil {
			t.Logf("poetry env remove --all failed (non-fatal): %v", err)
		}
	})

	for _, dep := range deps {
		mustRunPoetryCommand(t, dir, "add", dep.name+"=="+dep.version)
	}
}

// newPoetryProject initializes a clean Poetry project for use in testing.
func newPoetryProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	initPoetryProject(t, dir, nil)
	return dir
}

// poetryProjectTarget initializes a Poetry project with version as an
// installed dependency of poetryTarget.
func poetryProjectTarget(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	initPoetryProject(t, dir, []struct{ name, version string }{{poetryTarget, version}})
	return dir
}

// poetryProjectTargetLockOther initializes a Poetry project where
// installedVersion of poetryTarget is installed but lockedVersion is an
// as-yet uninstalled dependency of the project.
func poetryProjectTargetLockOther(t *testing.T, installedVersion, lockedVersion string) string {
	t.Helper()
	dir := poetryProjectTarget(t, installedVersion)
	mustRunPoetryCommand(t, dir, "add", "--lock", poetryTarget+"=="+lockedVersion)
	return dir
}

// poetryProjectLockLatest initializes a Poetry project where
// poetryTargetLatest is an as-yet uninstalled dependency.
func poetryProjectLockLatest(t *testing.T) string {
	t.Helper()
	dir := newPoetryProject(t)
	mustRunPoetryCommand(t, dir, "add", "--lock", poetryTarget+"=="+poetryTargetLatest)
	return dir
}

// poetryProjectTargetPreviousLooseConstraint initializes a Poetry project
// with poetryTarget locked at poetryTargetPrevious, but declared under an
// unconstrained requirement, so that `poetry update` is free to move it to
// the latest version.
func poetryProjectTargetPreviousLooseConstraint(t *testing.T) string {
	t.Helper()
	dir := poetryProjectTarget(t, poetryTargetPrevious)

	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	data, err := os.ReadFile(pyprojectPath)
	if err != nil {
		t.Fatalf("failed to read pyproject.toml: %v", err)
	}
	text := string(data)
	// Poetry >=2.0 declares dependencies as PEP 621 strings (e.g.
	// "idna (==3.17)"), while Poetry <2.0 uses the legacy
	// [tool.poetry.dependencies] table syntax (e.g. idna = "3.17").
	// Loosen whichever form is present.
	text = strings.ReplaceAll(text, poetryTarget+" (=="+poetryTargetPrevious+")", poetryTarget)
	text = strings.ReplaceAll(text, poetryTarget+` = "`+poetryTargetPrevious+`"`, poetryTarget+` = "*"`)
	if err := os.WriteFile(pyprojectPath, []byte(text), 0o644); err != nil {
		t.Fatalf("failed to write pyproject.toml: %v", err)
	}
	return dir
}

// poetryProjectNoLock initializes a Poetry project with poetryTarget as a
// declared dependency but no poetry.lock.
func poetryProjectNoLock(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustRunPoetryCommand(t, dir, "init", "--no-interaction", "--name", testPoetryProjectName)
	mustRunPoetryCommand(t, dir, "add", "--lock", poetryTarget+"=="+poetryTargetLatest)
	if err := os.Remove(filepath.Join(dir, "poetry.lock")); err != nil {
		t.Fatalf("failed to remove poetry.lock: %v", err)
	}
	return dir
}

// poetryShow returns the current state of packages installed via Poetry.
func poetryShow(t *testing.T, dir string) string {
	t.Helper()
	output := mustRunPoetryCommand(t, dir, "show")
	return strings.ToLower(string(output))
}

// CLI-assumption tests, mirroring tests/package_managers/test_poetry.py.

func TestPoetryVersionOutput(t *testing.T) {
	poetry := requireSystemPoetry(t)
	if poetry.versionErr != nil {
		t.Fatalf("failed to resolve version of real poetry executable %q: %v", poetry.Executable(), poetry.versionErr)
	}
	if poetry.version.Major == 0 && poetry.version.Minor == 0 && poetry.version.Patch == 0 {
		t.Fatalf("resolved a suspicious zero version for real poetry executable %q", poetry.Executable())
	}
}

func testPoetryNoChange(t *testing.T, project string, commands [][]string) {
	t.Helper()
	initState := poetryShow(t, project)
	for _, command := range commands {
		mustRunPoetryCommand(t, project, command[1:]...)
		if got := poetryShow(t, project); got != initState {
			t.Fatalf("poetry %v changed project state:\nbefore:\n%s\nafter:\n%s", command, initState, got)
		}
	}
}

func TestPoetryAddNoChange(t *testing.T) {
	requireSystemPoetry(t)
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "-V", "add", poetryTarget},
		{"poetry", "add", "-V", poetryTarget},
		{"poetry", "add", poetryTarget, "-V"},
		{"poetry", "--version", "add", poetryTarget},
		{"poetry", "add", "--version", poetryTarget},
		{"poetry", "add", poetryTarget, "--version"},
		{"poetry", "-h", "add", poetryTarget},
		{"poetry", "add", "-h", poetryTarget},
		{"poetry", "add", poetryTarget, "-h"},
		{"poetry", "--help", "add", poetryTarget},
		{"poetry", "add", "--help", poetryTarget},
		{"poetry", "add", poetryTarget, "--help"},
		{"poetry", "--dry-run", "add", poetryTarget},
		{"poetry", "add", "--dry-run", poetryTarget},
		{"poetry", "add", poetryTarget, "--dry-run"},
	}
	testPoetryNoChange(t, project, commands)
}

func TestPoetryInstallNoChange(t *testing.T) {
	requireSystemPoetry(t)
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "-V", "install"},
		{"poetry", "install", "-V"},
		{"poetry", "--version", "install"},
		{"poetry", "install", "--version"},
		{"poetry", "-h", "install"},
		{"poetry", "install", "-h"},
		{"poetry", "--help", "install"},
		{"poetry", "install", "--help"},
		{"poetry", "--dry-run", "install"},
		{"poetry", "install", "--dry-run"},
	}
	testPoetryNoChange(t, project, commands)
}

func TestPoetrySyncNoChange(t *testing.T) {
	poetry := requireSystemPoetry(t)
	if poetry.version.LessThan(poetryV2) {
		t.Skip("poetry sync requires Poetry >= 2.0")
	}
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "-V", "sync"},
		{"poetry", "sync", "-V"},
		{"poetry", "--version", "sync"},
		{"poetry", "sync", "--version"},
		{"poetry", "-h", "sync"},
		{"poetry", "sync", "-h"},
		{"poetry", "--help", "sync"},
		{"poetry", "sync", "--help"},
		{"poetry", "--dry-run", "sync"},
		{"poetry", "sync", "--dry-run"},
	}
	testPoetryNoChange(t, project, commands)
}

func TestPoetryUpdateNoChange(t *testing.T) {
	requireSystemPoetry(t)
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "-V", "update"},
		{"poetry", "update", "-V"},
		{"poetry", "--version", "update"},
		{"poetry", "update", "--version"},
		{"poetry", "-h", "update"},
		{"poetry", "update", "-h"},
		{"poetry", "--help", "update"},
		{"poetry", "update", "--help"},
		{"poetry", "--dry-run", "update"},
		{"poetry", "update", "--dry-run"},
	}
	testPoetryNoChange(t, project, commands)
}

func testPoetryErrorNoChange(t *testing.T, project string, commands [][]string) {
	t.Helper()
	initState := poetryShow(t, project)
	for _, command := range commands {
		if _, err := runPoetryCommand(t, project, command[1:]...); err == nil {
			t.Fatalf("poetry %v unexpectedly succeeded", command)
		}
		if got := poetryShow(t, project); got != initState {
			t.Fatalf("poetry %v changed project state despite erroring:\nbefore:\n%s\nafter:\n%s", command, initState, got)
		}
	}
}

func TestPoetryAddErrorNoChange(t *testing.T) {
	requireSystemPoetry(t)
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "add", "!a_nonexistent_p@ckage_name"},
		{"poetry", "add", "--dry-run", "!a_nonexistent_p@ckage_name"},
		{"poetry", "add", "--nonexistent-option", poetryTarget},
		{"poetry", "add", "-G", poetryTarget},
		{"poetry", "add", "--group", poetryTarget},
		{"poetry", "add", "-E", poetryTarget},
		{"poetry", "add", "--extras", poetryTarget},
		{"poetry", "add", "--python", poetryTarget},
		{"poetry", "add", "--platform", poetryTarget},
		{"poetry", "add", "--markers", poetryTarget},
		{"poetry", "add", "--source", poetryTarget},
		{"poetry", "add", "-P", poetryTarget},
		{"poetry", "add", "--project", poetryTarget},
		{"poetry", "add", "-C", poetryTarget},
		{"poetry", "add", "--directory", poetryTarget},
	}
	testPoetryErrorNoChange(t, project, commands)
}

func TestPoetryInstallErrorNoChange(t *testing.T) {
	requireSystemPoetry(t)
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "install", "unnecessary_argument"},
		{"poetry", "install", "--dry-run", "unnecessary_argument"},
		{"poetry", "install", "--nonexistent-option"},
		{"poetry", "install", "--without"},
		{"poetry", "install", "--with"},
		{"poetry", "install", "--only"},
		{"poetry", "install", "-E"},
		{"poetry", "install", "--extras"},
		{"poetry", "install", "-P"},
		{"poetry", "install", "--project"},
		{"poetry", "install", "-C"},
		{"poetry", "install", "--directory"},
	}
	testPoetryErrorNoChange(t, project, commands)
}

func TestPoetrySyncErrorNoChange(t *testing.T) {
	poetry := requireSystemPoetry(t)
	if poetry.version.LessThan(poetryV2) {
		t.Skip("poetry sync requires Poetry >= 2.0")
	}
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "sync", "unnecessary_argument"},
		{"poetry", "sync", "--dry-run", "unnecessary_argument"},
		{"poetry", "sync", "--nonexistent-option"},
		{"poetry", "sync", "--without"},
		{"poetry", "sync", "--with"},
		{"poetry", "sync", "--only"},
		{"poetry", "sync", "-E"},
		{"poetry", "sync", "--extras"},
		{"poetry", "sync", "-P"},
		{"poetry", "sync", "--project"},
		{"poetry", "sync", "-C"},
		{"poetry", "sync", "--directory"},
	}
	testPoetryErrorNoChange(t, project, commands)
}

func TestPoetryUpdateErrorNoChange(t *testing.T) {
	requireSystemPoetry(t)
	project := newPoetryProject(t)

	commands := [][]string{
		{"poetry", "update", "--nonexistent-option"},
		{"poetry", "update", "--nonexistent-option", poetryTarget},
		{"poetry", "update", "--without"},
		{"poetry", "update", poetryTarget, "--without"},
		{"poetry", "update", "--with"},
		{"poetry", "update", poetryTarget, "--with"},
		{"poetry", "update", "--only"},
		{"poetry", "update", poetryTarget, "--only"},
		{"poetry", "update", "-P"},
		{"poetry", "update", poetryTarget, "-P"},
		{"poetry", "update", "--project"},
		{"poetry", "update", poetryTarget, "--project"},
		{"poetry", "update", "-C"},
		{"poetry", "update", poetryTarget, "-C"},
		{"poetry", "update", "--directory"},
		{"poetry", "update", poetryTarget, "--directory"},
	}
	testPoetryErrorNoChange(t, project, commands)
}

func TestPoetryDryRunOutputInstall(t *testing.T) {
	poetry := requireSystemPoetry(t)

	isInstallLine := func(target, version, line string) bool {
		match := regexp.MustCompile(`Installing (?:the current project: )?(.*) \((.*)\)`).FindStringSubmatch(strings.TrimSpace(line))
		return match != nil && match[1] == target && match[2] == version && !strings.Contains(line, "Skipped")
	}

	newProject := newPoetryProject(t)
	lockLatestProject := poetryProjectLockLatest(t)

	tests := []struct {
		project       string
		command       []string
		target        string
		targetVersion string
		minVersion    *pm.Version
	}{
		{newProject, []string{"add", "--dry-run", poetryTarget}, poetryTarget, poetryTargetLatest, nil},
		{newProject, []string{"install", "--dry-run"}, testPoetryProjectName, "0.1.0", nil},
		{newProject, []string{"sync", "--dry-run"}, testPoetryProjectName, "0.1.0", &poetryV2},
		{lockLatestProject, []string{"update", "--dry-run"}, poetryTarget, poetryTargetLatest, nil},
	}

	for _, tc := range tests {
		if tc.minVersion != nil && poetry.version.LessThan(*tc.minVersion) {
			continue
		}
		output := mustRunPoetryCommand(t, tc.project, tc.command...)
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			if isInstallLine(tc.target, tc.targetVersion, line) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("poetry %v produced no install line for %s (%s); output:\n%s", tc.command, tc.target, tc.targetVersion, output)
		}
	}
}

func TestPoetryDryRunOutputUpdate(t *testing.T) {
	poetry := requireSystemPoetry(t)

	isUpdateLine := func(target, line string) bool {
		match := regexp.MustCompile(`Updating (.*) \((.*)\)`).FindStringSubmatch(strings.TrimSpace(line))
		return match != nil && match[1] == target && !strings.Contains(line, "Skipped")
	}

	previousProject := poetryProjectTarget(t, poetryTargetPrevious)
	previousLockLatestProject := poetryProjectTargetLockOther(t, poetryTargetPrevious, poetryTargetLatest)

	tests := []struct {
		project    string
		command    []string
		minVersion *pm.Version
	}{
		{previousProject, []string{"add", "--dry-run", poetryTarget + "==" + poetryTargetLatest}, nil},
		{previousLockLatestProject, []string{"install", "--dry-run"}, nil},
		{previousLockLatestProject, []string{"sync", "--dry-run"}, &poetryV2},
		{previousLockLatestProject, []string{"update", "--dry-run"}, nil},
	}

	for _, tc := range tests {
		if tc.minVersion != nil && poetry.version.LessThan(*tc.minVersion) {
			continue
		}
		output := mustRunPoetryCommand(t, tc.project, tc.command...)
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			if isUpdateLine(poetryTarget, line) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("poetry %v produced no update line for %s; output:\n%s", tc.command, poetryTarget, output)
		}
	}
}

func TestPoetryDryRunOutputDowngrade(t *testing.T) {
	poetry := requireSystemPoetry(t)

	isDowngradeLine := func(target, line string) bool {
		match := regexp.MustCompile(`(Updating|Downgrading) (.*) \((.*)\)`).FindStringSubmatch(strings.TrimSpace(line))
		return match != nil && match[2] == target && !strings.Contains(line, "Skipped")
	}

	latestProject := poetryProjectTarget(t, poetryTargetLatest)
	latestLockPreviousProject := poetryProjectTargetLockOther(t, poetryTargetLatest, poetryTargetPrevious)

	tests := []struct {
		project    string
		command    []string
		minVersion *pm.Version
	}{
		{latestProject, []string{"add", "--dry-run", poetryTarget + "==" + poetryTargetPrevious}, nil},
		{latestLockPreviousProject, []string{"install", "--dry-run"}, nil},
		{latestLockPreviousProject, []string{"sync", "--dry-run"}, &poetryV2},
		{latestLockPreviousProject, []string{"update", "--dry-run"}, nil},
	}

	for _, tc := range tests {
		if tc.minVersion != nil && poetry.version.LessThan(*tc.minVersion) {
			continue
		}
		output := mustRunPoetryCommand(t, tc.project, tc.command...)
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			if isDowngradeLine(poetryTarget, line) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("poetry %v produced no downgrade line for %s; output:\n%s", tc.command, poetryTarget, output)
		}
	}
}

// e2e tests of Poetry.ResolveInstallTargets, mirroring
// tests/package_managers/test_poetry_class.py.

func TestPoetryResolveInstallTargets_Add(t *testing.T) {
	poetry := requireSystemPoetry(t)

	newProject := newPoetryProject(t)
	latestProject := poetryProjectTarget(t, poetryTargetLatest)
	previousProject := poetryProjectTarget(t, poetryTargetPrevious)

	tests := []struct {
		name           string
		project        string
		targetSpec     string
		targetVersion  string
		registrySource bool // false for git/tarball URL sources, which have no publish date to resolve
	}{
		{"bare name", newProject, poetryTarget, poetryTargetLatest, true},
		{"@latest", newProject, poetryTarget + "@latest", poetryTargetLatest, true},
		{"pinned version", newProject, poetryTarget + "==" + poetryTargetLatest, poetryTargetLatest, true},
		{"git URL", newProject, "git+" + poetryTargetRepo, poetryTargetLatest, false},
		{"git URL with tag", newProject, "git+" + poetryTargetRepo + "#v" + poetryTargetLatest, poetryTargetLatest, false},
		{"git URL .git suffix", newProject, "git+" + poetryTargetRepo + ".git", poetryTargetLatest, false},
		{"git URL .git suffix with tag", newProject, "git+" + poetryTargetRepo + ".git#v" + poetryTargetLatest, poetryTargetLatest, false},
		{"tarball URL", newProject, poetryTargetRepo + "/archive/refs/tags/v" + poetryTargetLatest + ".tar.gz", poetryTargetLatest, false},
		{"downgrade from latest", latestProject, poetryTarget + "==" + poetryTargetPrevious, poetryTargetPrevious, true},
		{"downgrade git tag from latest", latestProject, "git+" + poetryTargetRepo + "#v" + poetryTargetPrevious, poetryTargetPrevious, false},
		{"upgrade from previous", previousProject, poetryTarget + "==" + poetryTargetLatest, poetryTargetLatest, true},
		{"upgrade git tag from previous", previousProject, "git+" + poetryTargetRepo + "#v" + poetryTargetLatest, poetryTargetLatest, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			initState := poetryShow(t, tc.project)

			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			targets, err := poetry.ResolveInstallTargets(ctx, []string{"add", "--directory", tc.project, tc.targetSpec})
			if err != nil {
				t.Fatalf("ResolveInstallTargets() returned unexpected error: %v", err)
			}

			if targets.Len() != 1 {
				t.Fatalf("ResolveInstallTargets() = %v, want exactly 1 target", targets)
			}
			var got pm.Package
			for pkg := range targets.Items() {
				got = pkg
			}
			if got.Ecosystem != ecosystem.PYPI || got.Name != poetryTarget || got.Version != tc.targetVersion || got.Source == "" {
				t.Fatalf("ResolveInstallTargets() = %+v, want {Ecosystem:%s Name:%s Version:%s Source:<non-empty>}", got, ecosystem.PYPI, poetryTarget, tc.targetVersion)
			}
			if tc.registrySource {
				if want := testPackagePublishDates[tc.targetVersion]; !got.PublishDate.Equal(want) {
					t.Fatalf("ResolveInstallTargets() = %+v, want PublishDate = %v", got, want)
				}
			} else if !got.PublishDate.IsZero() {
				t.Fatalf("ResolveInstallTargets() = %+v, want zero PublishDate for a non-registry source", got)
			}

			if got := poetryShow(t, tc.project); got != initState {
				t.Fatalf("ResolveInstallTargets() modified project state:\nbefore:\n%s\nafter:\n%s", initState, got)
			}
		})
	}
}

// checkPoetryResolveInstallTargets asserts that resolving install targets for
// command against project yields exactly want, and doesn't modify the
// project's installed state.
func checkPoetryResolveInstallTargets(t *testing.T, poetry Poetry, command []string, project string, want []pm.Package) {
	t.Helper()

	initState := poetryShow(t, project)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	targets, err := poetry.ResolveInstallTargets(ctx, command)
	if err != nil {
		t.Fatalf("ResolveInstallTargets(%v) returned unexpected error: %v", command, err)
	}

	if targets.Len() != len(want) {
		t.Fatalf("ResolveInstallTargets(%v) = %v, want %v", command, targets, want)
	}
	for _, w := range want {
		if !targets.Contains(w) {
			t.Fatalf("ResolveInstallTargets(%v) missing expected target %+v; got %v", command, w, targets)
		}
	}

	if got := poetryShow(t, project); got != initState {
		t.Fatalf("ResolveInstallTargets(%v) modified project state:\nbefore:\n%s\nafter:\n%s", command, initState, got)
	}
}

func rootProjectPackage() pm.Package {
	return pm.Package{Ecosystem: ecosystem.PYPI, Name: testPoetryProjectName, Version: "0.1.0"}
}

func TestPoetryResolveInstallTargets_Install(t *testing.T) {
	poetry := requireSystemPoetry(t)

	newProject := newPoetryProject(t)
	latestProject := poetryProjectTarget(t, poetryTargetLatest)
	latestLockPreviousProject := poetryProjectTargetLockOther(t, poetryTargetLatest, poetryTargetPrevious)
	previousLockLatestProject := poetryProjectTargetLockOther(t, poetryTargetPrevious, poetryTargetLatest)

	tests := []struct {
		project string
		want    []pm.Package
	}{
		{newProject, []pm.Package{rootProjectPackage()}},
		{latestProject, []pm.Package{rootProjectPackage()}},
		{latestLockPreviousProject, []pm.Package{rootProjectPackage(), poetryTargetPackage(poetryTargetPrevious)}},
		{previousLockLatestProject, []pm.Package{rootProjectPackage(), poetryTargetPackage(poetryTargetLatest)}},
	}

	for _, tc := range tests {
		checkPoetryResolveInstallTargets(t, poetry, []string{"install", "--directory", tc.project}, tc.project, tc.want)
	}
}

func TestPoetryResolveInstallTargets_Sync(t *testing.T) {
	poetry := requireSystemPoetry(t)
	if poetry.version.LessThan(poetryV2) {
		t.Skip("poetry sync requires Poetry >= 2.0")
	}

	newProject := newPoetryProject(t)
	latestProject := poetryProjectTarget(t, poetryTargetLatest)
	previousProject := poetryProjectTarget(t, poetryTargetPrevious)
	latestLockPreviousProject := poetryProjectTargetLockOther(t, poetryTargetLatest, poetryTargetPrevious)
	previousLockLatestProject := poetryProjectTargetLockOther(t, poetryTargetPrevious, poetryTargetLatest)

	tests := []struct {
		project string
		want    []pm.Package
	}{
		{newProject, []pm.Package{rootProjectPackage()}},
		{latestProject, []pm.Package{rootProjectPackage()}},
		{previousProject, []pm.Package{rootProjectPackage()}},
		{latestLockPreviousProject, []pm.Package{rootProjectPackage(), poetryTargetPackage(poetryTargetPrevious)}},
		{previousLockLatestProject, []pm.Package{rootProjectPackage(), poetryTargetPackage(poetryTargetLatest)}},
	}

	for _, tc := range tests {
		checkPoetryResolveInstallTargets(t, poetry, []string{"sync", "--directory", tc.project}, tc.project, tc.want)
	}
}

func TestPoetryResolveInstallTargets_Update(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := poetryProjectTargetPreviousLooseConstraint(t)

	checkPoetryResolveInstallTargets(
		t, poetry, []string{"update", "--directory", project}, project,
		[]pm.Package{poetryTargetPackage(poetryTargetLatest)},
	)
}

func TestPoetryResolveInstallTargets_PyPISource(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := poetryProjectTargetLockOther(t, poetryTargetPrevious, poetryTargetLatest)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	targets, err := poetry.ResolveInstallTargets(ctx, []string{"install", "--directory", project})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() returned unexpected error: %v", err)
	}

	found := false
	for pkg := range targets.Items() {
		if pkg.Name != testPoetryProjectName {
			found = true
			if !strings.HasPrefix(pkg.Source, "https://pypi.org/") {
				t.Fatalf("target %+v has non-PyPI source", pkg)
			}
		}
	}
	if !found {
		t.Fatalf("ResolveInstallTargets() resolved no third-party targets: %v", targets)
	}
}

func TestGetPoetrySourceMap_NoLock(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := poetryProjectNoLock(t)

	if _, err := os.Stat(filepath.Join(project, "poetry.lock")); !os.IsNotExist(err) {
		t.Fatalf("expected no poetry.lock in the test project, got err = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	sourceMap := getPoetrySourceMap(ctx, poetry.Executable(), []string{"install", "--directory", project})

	if len(sourceMap) == 0 {
		t.Fatal("getPoetrySourceMap() returned an empty map")
	}

	foundTarget := false
	for key, source := range sourceMap {
		if key.name == poetryTarget {
			foundTarget = true
			if !strings.HasPrefix(source, "https://pypi.org/") {
				t.Fatalf("sourceMap[%+v] = %q, want a pypi.org URL", key, source)
			}
		}
	}
	if !foundTarget {
		t.Fatalf("getPoetrySourceMap() has no entry for %s: %v", poetryTarget, sourceMap)
	}

	if _, err := os.Stat(filepath.Join(project, "poetry.lock")); !os.IsNotExist(err) {
		t.Fatalf("expected getPoetrySourceMap() not to create poetry.lock in the real project, got err = %v", err)
	}
}

// TestPoetryResolveInstallTargets_Gating exercises Poetry.ResolveInstallTargets'
// own gating logic (uninspected subcommands, dry-run skip options) directly,
// mirroring the analogous TestResolveInstallTargets_DryRunGating in
// pip_test.go and TestNpmResolveInstallTargets_DryRunGating in npm_test.go.
func TestPoetryResolveInstallTargets_Gating(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := newPoetryProject(t)

	tests := []struct {
		name       string
		command    []string
		hasTargets bool
	}{
		{"plain install", []string{"install", "--directory", project}, true},
		{"-V before install", []string{"-V", "install", "--directory", project}, false},
		{"--version before install", []string{"--version", "install", "--directory", project}, false},
		{"-h before install", []string{"-h", "install", "--directory", project}, false},
		{"install -h", []string{"install", "-h", "--directory", project}, false},
		{"--help before install", []string{"--help", "install", "--directory", project}, false},
		{"install --help", []string{"install", "--help", "--directory", project}, false},
		{"--dry-run before install", []string{"--dry-run", "install", "--directory", project}, false},
		{"install --dry-run", []string{"install", "--dry-run", "--directory", project}, false},
		{"non-inspected subcommand (show)", []string{"show", "--directory", project}, false},
		{"non-inspected subcommand (check)", []string{"check", "--directory", project}, false},
		{"empty command", []string{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			targets, err := poetry.ResolveInstallTargets(ctx, tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) returned unexpected error: %v", tc.command, err)
			}
			if got := targets.Len() > 0; got != tc.hasTargets {
				t.Fatalf("ResolveInstallTargets(%v) has targets = %v, want %v", tc.command, got, tc.hasTargets)
			}
		})
	}
}

// TestPoetryResolveInstallTargets_ErrorPaths verifies that an erroring
// add/install command resolves to an empty target set (rather than an error),
// through both of Poetry.ResolveInstallTargets' two resolution strategies:
// resolveLockRegenTargets (for add/update) and resolveDryRunTargets (for
// install/sync).
func TestPoetryResolveInstallTargets_ErrorPaths(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := newPoetryProject(t)

	tests := []struct {
		name    string
		command []string
	}{
		{"add: nonexistent package (lock regen path)", []string{"add", "--directory", project, "!a_nonexistent_p@ckage_name"}},
		{"install: nonexistent option (dry-run path)", []string{"install", "--directory", project, "--nonexistent-option"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			targets, err := poetry.ResolveInstallTargets(ctx, tc.command)
			if err != nil {
				t.Fatalf("ResolveInstallTargets(%v) returned unexpected error: %v", tc.command, err)
			}
			if targets.Len() != 0 {
				t.Fatalf("ResolveInstallTargets(%v) = %v, want an empty set for an erroring command", tc.command, targets)
			}
		})
	}
}

// TestPoetryResolveInstallTargets_VersionGating verifies that
// ResolveInstallTargets rejects a command outright, without invoking any
// subprocess, when the Poetry executable's version is unknown or too old.
// Constructing the Poetry value directly (rather than via a real
// executable) keeps this test fast and independent of the system's poetry.
func TestPoetryResolveInstallTargets_VersionGating(t *testing.T) {
	tests := []struct {
		name   string
		poetry Poetry
	}{
		{"version resolution failed", Poetry{versionErr: errors.New("boom")}},
		{"version too old", Poetry{version: pm.Version{Major: 1, Minor: 0}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.poetry.ResolveInstallTargets(context.Background(), []string{"add", "somepkg"})
			if !errors.Is(err, pm.ErrUnsupportedVersion) {
				t.Fatalf("ResolveInstallTargets() returned %v, want an error wrapping ErrUnsupportedVersion", err)
			}
		})
	}
}

// TestPoetryResolveInstallTargets_CwdFallback verifies that
// ResolveInstallTargets resolves a command's project directory via the
// current working directory when no --directory/-C flag is present, rather
// than only via the flag-parsing path already covered in isolation by
// TestResolvePoetryProjectDir_NoFlagFallsBackToCwd.
func TestPoetryResolveInstallTargets_CwdFallback(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := newPoetryProject(t)
	chdirT(t, project)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	targets, err := poetry.ResolveInstallTargets(ctx, []string{"install"})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() returned unexpected error: %v", err)
	}

	if targets.Len() != 1 {
		t.Fatalf("ResolveInstallTargets() = %v, want exactly 1 target", targets)
	}
	for pkg := range targets.Items() {
		if pkg.Name != testPoetryProjectName {
			t.Fatalf("ResolveInstallTargets() = %+v, want the root project package %q", pkg, testPoetryProjectName)
		}
	}
}

func TestParsePoetryLockFile_MalformedTOML(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "poetry.lock")
	if err := os.WriteFile(lockPath, []byte("this is not valid TOML [[["), 0o644); err != nil {
		t.Fatalf("failed to write test lock file: %v", err)
	}

	if _, err := parsePoetryLockFile(lockPath); err == nil {
		t.Fatal("parsePoetryLockFile() = nil error, want error for a malformed lock file")
	}
}

// TestPoetryResolveInstallTargets_LocalPathDependency verifies that adding a
// local directory dependency resolves its source to an absolute path via a
// real poetry.lock regeneration, not just the synthetic TOML fixtures
// exercised by TestParsePoetryLockFile_LocalSource.
func TestPoetryResolveInstallTargets_LocalPathDependency(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := newPoetryProject(t)

	localPkgDir := t.TempDir()
	mustRunPoetryCommand(t, localPkgDir, "init", "--no-interaction", "--name", "local-lib")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	targets, err := poetry.ResolveInstallTargets(ctx, []string{"add", "--directory", project, localPkgDir})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() returned unexpected error: %v", err)
	}

	if targets.Len() != 1 {
		t.Fatalf("ResolveInstallTargets() = %v, want exactly 1 target", targets)
	}
	var got pm.Package
	for pkg := range targets.Items() {
		got = pkg
	}
	want := resolvedAbs(t, localPkgDir)
	if got.Ecosystem != ecosystem.PYPI || got.Name != "local-lib" || resolvedAbs(t, got.Source) != want {
		t.Fatalf("ResolveInstallTargets() = %+v, want {Ecosystem:%s Name:local-lib Source:%s}", got, ecosystem.PYPI, want)
	}
}

// TestPoetryResolveInstallTargets_MultiplePackages verifies that a single
// add command naming several new packages resolves all of them, not just
// the one exercised end-to-end by the single-target cases above.
func TestPoetryResolveInstallTargets_MultiplePackages(t *testing.T) {
	poetry := requireSystemPoetry(t)
	project := newPoetryProject(t)

	const other = "six"
	const otherVersion = "1.16.0"

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	targets, err := poetry.ResolveInstallTargets(ctx, []string{
		"add", "--directory", project,
		poetryTarget + "==" + poetryTargetLatest,
		other + "==" + otherVersion,
	})
	if err != nil {
		t.Fatalf("ResolveInstallTargets() returned unexpected error: %v", err)
	}

	want := map[string]string{poetryTarget: poetryTargetLatest, other: otherVersion}
	if targets.Len() != len(want) {
		t.Fatalf("ResolveInstallTargets() = %v, want %d targets", targets, len(want))
	}
	for pkg := range targets.Items() {
		wantVersion, ok := want[pkg.Name]
		if !ok || pkg.Version != wantVersion || pkg.Ecosystem != ecosystem.PYPI || pkg.Source == "" {
			t.Fatalf("ResolveInstallTargets() contains unexpected target %+v", pkg)
		}
		delete(want, pkg.Name)
	}
	if len(want) != 0 {
		t.Fatalf("ResolveInstallTargets() missing expected targets %v", want)
	}
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
