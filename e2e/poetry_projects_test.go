//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type poetryProjectState struct {
	directory, python, otherPython string
	args                           []string
	before                         map[string]string
	target, previous, leaf         candidate
	installed                      bool
	caller                         *fileEvidence
}

func init() {
	for _, mode := range []string{"resolution", "proxy"} {
		add := func(id, variant string, blocked bool) {
			action := "allow"
			if blocked {
				action = "block"
			}
			suites["poetry-projects"] = append(suites["poetry-projects"], scenario{Scenario: id, Variant: mode + "-" + variant + "-" + action, Manager: "poetry", Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "poetry-uv-graph", Capabilities: []string{"poetry-modern"}, Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runPoetryProject(r, variant, blocked) }})
		}
		for _, variant := range []string{"fresh-install", "sync-current", "add-upgrade", "add-downgrade", "update-stale"} {
			for _, blocked := range []bool{false, true} {
				add("POETRY-01", variant, blocked)
			}
		}
		add("POETRY-01", "update-current", false)
		for _, variant := range []string{"directory-long", "directory-short", "directory-symlink-parent"} {
			add("POETRY-04", variant, false)
			add("POETRY-04", variant, true)
		}
		for _, variant := range []string{"stale-install", "missing-release", "native-install-failure"} {
			add("CORE-14", variant, false)
		}
		if mode == "proxy" {
			for _, variant := range []string{"metadata-lock-fresh", "metadata-regenerate", "metadata-add-lock"} {
				add("POETRY-02", variant, false)
			}
		}
		for _, informational := range []bool{false, true} {
			name := "inspected-rejection"
			if informational {
				name = "informational"
			}
			suites["poetry-projects"] = append(suites["poetry-projects"], scenario{Scenario: "CORE-11", Variant: mode + "-legacy-" + name, Manager: "poetry", Mode: mode, Backend: "local", RegistryProfile: "none", Capabilities: []string{"poetry-legacy"}, Timeout: time.Minute, Run: func(r *caseRun) error { return runPoetryLegacy(r, informational) }})
		}
	}
}

func poetryProjectInputs(r *caseRun) (projectGraphSelection, error) {
	var selection projectGraphSelection
	pins, err := loadPipGraph(r.Candidate)
	if err != nil {
		return selection, err
	}
	if pins.Cell.ID != r.Cell.ID || pins.Cell.Executable != r.Cell.Executable || pins.Cell.ManagerVersion != r.Cell.ManagerVersion {
		return selection, fmt.Errorf("project locks belong to another cell")
	}
	if err := readJSON(r.Candidate.Selection.Path, &selection); err != nil {
		return selection, err
	}
	if len(selection.Manifests) != 2 {
		return selection, fmt.Errorf("missing native project manifests")
	}
	return selection, nil
}
func copyPoetryProjectInput(evidence fileEvidence, destination string) error {
	if err := verifyGraphFile(evidence); err != nil {
		return err
	}
	data, err := os.ReadFile(evidence.Path)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0600)
}
func setupPoetryProject(r *caseRun, selection projectGraphSelection, variant string) (poetryProjectState, error) {
	initial, target := 0, 0
	installed := variant == "add-upgrade" || variant == "add-downgrade" || variant == "update-stale" || variant == "update-current"
	if variant == "add-upgrade" || variant == "update-stale" || variant == "stale-install" {
		initial = 1
	}
	if variant == "add-downgrade" {
		target = 1
	}
	r.Candidate = selection.Roots[initial]
	python, err := prepareProjectGraph(r)
	state := poetryProjectState{directory: r.WorkDir, python: python, target: selection.Roots[target], previous: selection.Roots[initial], leaf: selection.Leaves[target], installed: installed}
	if err != nil {
		return state, err
	}
	for _, ev := range []fileEvidence{selection.Manifests[initial], selection.Reports[initial]} {
		if err := copyPoetryProjectInput(ev, filepath.Join(r.WorkDir, filepath.Base(ev.Path))); err != nil {
			return state, err
		}
	}
	if _, err := r.Command("git-init", r.Cell.Git, "init", "--quiet"); err != nil {
		return state, err
	}
	if _, err := r.Command("git-origin", r.Cell.Git, "remote", "add", "origin", "https://example.invalid/poetry-project.git"); err != nil {
		return state, err
	}
	if installed {
		if _, err := r.Command("native-initial-install", r.Cell.Executable, "--no-interaction", "install", "--no-root"); err != nil {
			return state, err
		}
	}
	r.Env["POETRY_CACHE_DIR"] = filepath.Join(r.Root, "protected-cache")
	if err := os.MkdirAll(r.Env["POETRY_CACHE_DIR"], 0700); err != nil {
		return state, err
	}
	r.Candidate = state.target
	state.args = []string{"--no-interaction", "install", "--no-root"}
	switch variant {
	case "fresh-install", "metadata-lock-fresh":
		if err := os.Remove(filepath.Join(r.WorkDir, "poetry.lock")); err != nil {
			return state, err
		}
		if variant == "metadata-lock-fresh" {
			state.args = []string{"--no-interaction", "lock"}
		}
	case "sync-current":
		state.args = []string{"--no-interaction", "sync", "--no-root"}
	case "add-upgrade", "add-downgrade":
		state.args = []string{"--no-interaction", "add", state.target.Project + "==" + state.target.Version}
	case "update-stale", "stale-install":
		if err := writeProjectGraphManifest(r); err != nil {
			return state, err
		}
		if variant == "update-stale" {
			state.args = []string{"--no-interaction", "update", state.target.Project}
		}
	case "update-current":
		state.args = []string{"--no-interaction", "update", state.target.Project}
	case "missing-release":
		state.args = []string{"--no-interaction", "add", state.target.Project + "==0.0.0+scfw.missing"}
	case "native-install-failure":
		path := filepath.Join(r.WorkDir, "pyproject.toml")
		body, err := os.ReadFile(path)
		if err != nil {
			return state, err
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(body), "package-mode = false", "package-mode = true", 1)), 0600); err != nil {
			return state, err
		}
		state.args = []string{"--no-interaction", "install"}
	case "metadata-regenerate":
		if _, err := r.Command("prime-metadata", r.Cell.Executable, "--no-interaction", "lock", "--regenerate"); err != nil {
			return state, err
		}
		if err := projectGraphCache(r, "metadata-only", state.leaf, true, false); err != nil {
			return state, err
		}
		if err := copyPoetryProjectInput(selection.Reports[1], filepath.Join(r.WorkDir, "poetry.lock")); err != nil {
			return state, err
		}
		state.args = []string{"--no-interaction", "lock", "--regenerate"}
	case "metadata-add-lock":
		r.Candidate = candidate{}
		if err := writeProjectGraphManifest(r); err != nil {
			return state, err
		}
		if _, err := r.Command("empty-lock", r.Cell.Executable, "--no-interaction", "lock"); err != nil {
			return state, err
		}
		r.Candidate = state.target
		state.args = []string{"--no-interaction", "add", state.target.Project + "==" + state.target.Version, "--lock"}
	}
	if strings.HasPrefix(variant, "directory-") {
		caller := filepath.Join(r.Root, "caller")
		if err := os.MkdirAll(caller, 0700); err != nil {
			return state, err
		}
		copy := *r
		copy.WorkDir = caller
		copy.Candidate = candidate{}
		if err := writeProjectGraphManifest(&copy); err != nil {
			return state, err
		}
		ev, err := digestFile(filepath.Join(caller, "pyproject.toml"))
		if err != nil {
			return state, err
		}
		state.caller = &ev
		path, flag := state.directory, "--directory"
		if variant == "directory-short" {
			flag = "-C"
		}
		if variant == "directory-symlink-parent" {
			nested := filepath.Join(state.directory, "nested")
			if err := os.Mkdir(nested, 0700); err != nil {
				return state, err
			}
			link := filepath.Join(caller, "link")
			if err := os.Symlink(nested, link); err != nil {
				return state, err
			}
			path = link + "/.."
		}
		callerPython := filepath.Join(caller, ".venv", "bin", "python")
		if _, err := r.Command("caller-venv", r.Cell.Runtime, "-m", "venv", "--without-pip", filepath.Dir(filepath.Dir(callerPython))); err != nil {
			return state, err
		}
		r.WorkDir = caller
		state.args = append([]string{flag, path}, state.args...)
		control, err := r.Command("native-directory-environment", r.Cell.Executable, flag, path, "env", "info", "--executable")
		if err != nil {
			return state, err
		}
		body, err := os.ReadFile(control.Stdout.Path)
		if err != nil {
			return state, err
		}
		nativePython := filepath.Clean(strings.TrimSpace(string(body)))
		if nativePython != state.python && nativePython != callerPython {
			return state, fmt.Errorf("native directory selected an environment outside isolated projects: %s", nativePython)
		}
		state.otherPython = callerPython
		if nativePython == callerPython {
			state.python, state.otherPython = callerPython, state.python
		}
		r.Result.Observations["native_install_interpreter"] = nativePython
	}
	state.before, err = poetryLifecycleSnapshot(state.directory)
	return state, err
}

func poetryLifecycleSnapshot(directory string) (map[string]string, error) {
	snapshot := map[string]string{}
	for _, name := range []string{"pyproject.toml", "poetry.lock"} {
		body, err := os.ReadFile(filepath.Join(directory, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		snapshot[name] = string(body)
	}
	return snapshot, nil
}
func poetryProjectInstalled(r *caseRun, state poetryProjectState, blocked, nativeFailure bool) error {
	script, err := filepath.Abs(filepath.Join(poetryFixtures, "inspect_install.py"))
	if err != nil {
		return err
	}
	for _, python := range []string{state.python, state.otherPython} {
		if python == "" {
			continue
		}
		for _, node := range []candidate{state.target, state.leaf} {
			if python == state.python && blocked && r.Spec.Mode == "proxy" && node.Project == state.leaf.Project {
				continue // Poetry may install an allowed dependency before the blocked root.
			}
			command, err := r.Command("installed-state", python, "-I", script, node.Project, node.Module)
			if err != nil {
				return err
			}
			var actual struct {
				Present, Imported bool
				Version           string
			}
			if err := readJSON(command.Stdout.Path, &actual); err != nil {
				return err
			}
			present := python == state.python && (!blocked && !nativeFailure || state.installed)
			expected := node.Version
			if blocked && node.Project == state.target.Project && state.installed {
				expected = state.previous.Version
			}
			if python == state.python && blocked && r.Spec.Mode == "proxy" && state.installed && !actual.Present {
				continue
			}
			if actual.Present != present || present && (!actual.Imported || actual.Version != expected) {
				return fmt.Errorf("installed %s state=%+v want present=%t version=%s", node.Project, actual, present, expected)
			}
		}
	}
	return nil
}
func runPoetryProject(r *caseRun, variant string, blocked bool) error {
	selection, err := poetryProjectInputs(r)
	if err != nil {
		return err
	}
	failureMessage := map[string]string{
		"stale-install":          "pyproject.toml changed significantly since poetry.lock was last generated",
		"missing-release":        "Could not find a matching version of package",
		"native-install-failure": "No file/folder found for package",
	}[variant]
	failure := failureMessage != ""
	nativeExit := 0
	if failure {
		control := *r
		control.Root = filepath.Join(r.Root, "native-control")
		control.WorkDir = filepath.Join(control.Root, "work")
		control.Env, err = isolatedEnvironment(control.Root)
		if err != nil {
			return err
		}
		state, err := setupPoetryProject(&control, selection, variant)
		if err != nil {
			return err
		}
		command, err := control.Command("native-failure", append([]string{r.Cell.Executable}, state.args...)...)
		if command.TimedOut || command.ExitCode <= 0 {
			return fmt.Errorf("native failure control exit=%d: %v", command.ExitCode, err)
		}
		stderr, err := os.ReadFile(command.Stderr.Path)
		if err != nil || !strings.Contains(string(stderr), failureMessage) {
			return fmt.Errorf("native control failed for an unexpected reason: %s: %v", stderr, err)
		}
		nativeExit = command.ExitCode
	}
	state, err := setupPoetryProject(r, selection, variant)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "before", state.before); err != nil {
		return err
	}
	metadata := strings.HasPrefix(variant, "metadata-")
	if blocked || metadata {
		if err := writeFinding(r, "PyPI", state.target.Project, state.target.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	command, commandErr := r.Command("scfw", append([]string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", "poetry"}, state.args...)...)
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	wantExit := nativeExit
	if blocked {
		wantExit = 1
	}
	if command.ExitCode != wantExit {
		return fmt.Errorf("Poetry %s exit=%d want%d: %v", variant, command.ExitCode, wantExit, commandErr)
	}
	after, err := poetryLifecycleSnapshot(state.directory)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "after", after); err != nil {
		return err
	}
	if blocked && r.Spec.Mode == "resolution" || failure && variant != "native-install-failure" {
		if len(after) != len(state.before) {
			return fmt.Errorf("denied/failing command changed lock existence")
		}
		for path, body := range state.before {
			if after[path] != body {
				return fmt.Errorf("denied/failing command changed %s", path)
			}
		}
	}
	if state.caller != nil {
		if err := verifyGraphFile(*state.caller); err != nil {
			return err
		}
	}
	noTargets := variant == "update-current" || failure && variant != "native-install-failure"
	if metadata {
		noTargets = true
	}
	if err := assertGraphPolicy(r, []candidate{state.target}, blocked, noTargets); err != nil {
		return err
	}
	if !noTargets {
		records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
		if err != nil {
			return err
		}
		for _, record := range records {
			if record.Repository != "https://example.invalid/poetry-project.git" {
				return fmt.Errorf("wrong project repository: %s", record.Repository)
			}
		}
	}
	if err := poetryProjectInstalled(r, state, blocked, metadata || failure && variant != "native-install-failure"); err != nil {
		return err
	}
	if !blocked && (!failure || variant == "native-install-failure") {
		nodes, err := inspectProjectGraph(r, filepath.Join(state.directory, "poetry.lock"), state.target.Project, state.leaf.Project)
		if err != nil {
			return err
		}
		if err := matchProjectGraph(nodes, state.target, state.leaf); err != nil {
			return err
		}
		if metadata {
			if err := projectGraphCache(r, "metadata-after", state.leaf, true, false); err != nil {
				return err
			}
			r.Result.Observations["distribution_requests"] = "none observed; exact BLOCK finding did not become a package decision during metadata-only work"
		} else if variant != "update-current" {
			ev, err := poetryDownloadedArchive(r.Env["POETRY_CACHE_DIR"], state.target)
			if err != nil {
				return err
			}
			r.Result.Evidence["resulting-artifact"] = ev
		}
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("wrong Poetry mode")
	}
	if failure {
		if !strings.Contains(string(stderr), failureMessage) {
			return fmt.Errorf("SCFW failure differs from native manager failure: %s", stderr)
		}
		r.Result.Observations["native_exit"] = nativeExit
		r.Result.ResolvedAction = "MANAGER_FAILURE"
	}
	remains, err := filepath.Glob(filepath.Join(r.Root, ".scfw-poetry-*"))
	if err != nil {
		return err
	}
	if len(remains) != 0 {
		return fmt.Errorf("temporary projects remain: %v", remains)
	}
	return assertCleanup(r, string(stderr))
}

func runPoetryLegacy(r *caseRun, informational bool) error {
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	operation := "install"
	if informational {
		operation = "--version"
	}
	command, commandErr := r.Command("legacy", r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", "poetry", operation)
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if informational {
		if command.ExitCode != 0 {
			return commandErr
		}
		stdout, err := os.ReadFile(command.Stdout.Path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(stdout), r.Cell.ManagerVersion) {
			return fmt.Errorf("wrong legacy informational version")
		}
		if _, err := readPolicy(r.Env["SCFW_LOG_FILE"]); !os.IsNotExist(err) {
			return fmt.Errorf("informational command produced policy: %v", err)
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "ALLOW"
	} else {
		if command.ExitCode == 0 || !strings.Contains(string(stderr), "poetry before v2.0.0 is not supported") {
			return fmt.Errorf("missing Poetry legacy guard: exit%d: %v", command.ExitCode, commandErr)
		}
		if _, err := readPolicy(r.Env["SCFW_LOG_FILE"]); !os.IsNotExist(err) {
			return fmt.Errorf("legacy guard produced policy: %v", err)
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "REJECT"
	}
	direct := *r
	direct.Spec.Mode = "direct"
	if strings.Contains(string(stderr), "started package manager proxy") {
		return fmt.Errorf("legacy guard/information started a proxy")
	}
	return assertCleanup(&direct, string(stderr))
}
