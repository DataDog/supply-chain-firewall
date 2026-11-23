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

func init() {
	for _, mode := range []string{"resolution", "proxy"} {
		for _, form := range []string{"long", "equals", "short", "attached", "relative", "subdirectory", "symlink-parent"} {
			for _, blocked := range []bool{false, true} {
				action := "allow"
				if blocked {
					action = "block"
				}
				suites["poetry-project-selection"] = append(suites["poetry-project-selection"], scenario{Scenario: "POETRY-04", Variant: mode + "-project-" + form + "-" + action, Manager: "poetry", Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "pypi-old", Timeout: 4 * time.Minute, Run: func(r *caseRun) error { return runPoetryProjectSelection(r, form, blocked) }})
			}
		}
	}
}

func runPoetryProjectSelection(r *caseRun, form string, blocked bool) error {
	python, err := preparePoetry(r, "add")
	if err != nil {
		return err
	}
	selected := r.WorkDir
	if _, err := r.Command("selected-origin", r.Cell.Git, "remote", "set-url", "origin", "https://example.invalid/selected.git"); err != nil {
		return err
	}
	before, err := poetryProjectSnapshot(selected)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "before", before); err != nil {
		return err
	}
	caller := *r
	caller.Root = filepath.Join(r.Root, "caller")
	caller.Env, err = isolatedEnvironment(caller.Root)
	if err != nil {
		return err
	}
	if _, err := preparePoetry(&caller, "add"); err != nil {
		return err
	}
	if _, err := caller.Command("caller-origin", r.Cell.Git, "remote", "set-url", "origin", "https://example.invalid/caller.git"); err != nil {
		return err
	}
	callerBefore, err := poetryProjectSnapshot(caller.WorkDir)
	if err != nil {
		return err
	}
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	if blocked {
		if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	path := selected
	if form == "subdirectory" || form == "symlink-parent" {
		nested := filepath.Join(selected, "nested")
		if err := os.Mkdir(nested, 0700); err != nil {
			return err
		}
		path = nested
		if form == "symlink-parent" {
			link := filepath.Join(caller.WorkDir, "linked-project")
			if err := os.Symlink(nested, link); err != nil {
				return err
			}
			path = link + "/.."
		}
	}
	selector := []string{"--project", path}
	switch form {
	case "equals":
		selector = []string{"--project=" + path}
	case "short":
		selector = []string{"-P", path}
	case "attached":
		selector = []string{"-P" + path}
	case "relative":
		selector = []string{"--directory", filepath.Dir(selected), "--project", filepath.Base(selected)}
	}
	r.WorkDir = caller.WorkDir
	nativeArgs := append([]string{r.Cell.Executable, "--no-interaction"}, selector...)
	native, err := r.Command("native-environment", append(nativeArgs, "env", "info", "--executable")...)
	if err != nil {
		return err
	}
	output, err := os.ReadFile(native.Stdout.Path)
	if err != nil {
		return err
	}
	nativePython := filepath.Clean(strings.TrimSpace(string(output)))
	callerPython := filepath.Join(caller.WorkDir, ".venv", "bin", "python")
	if nativePython != python && nativePython != callerPython {
		return fmt.Errorf("native selected an environment outside the two isolated projects: %s", nativePython)
	}
	r.Result.Observations["native_install_interpreter"] = nativePython
	args := []string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", "poetry", "--no-interaction"}
	args = append(args, selector...)
	args = append(args, "add", r.Candidate.Project+"=="+r.Candidate.Version)
	command, commandErr := r.Command("selected-add", args...)
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if (command.ExitCode != 0) != blocked {
		return fmt.Errorf("selected add exit=%d blocked=%t: %v", command.ExitCode, blocked, commandErr)
	}
	if err := assertPoetryUnchanged(caller.WorkDir, callerBefore); err != nil {
		return fmt.Errorf("unselected caller changed: %w", err)
	}
	if blocked && r.Spec.Mode == "resolution" {
		if err := assertPoetryUnchanged(selected, before); err != nil {
			return err
		}
	}
	after, err := poetryProjectSnapshot(selected)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "after", after); err != nil {
		return err
	}
	if !blocked && (after["pyproject.toml"] == before["pyproject.toml"] || after["poetry.lock"] == before["poetry.lock"]) {
		return fmt.Errorf("approved add did not update the selected project")
	}
	if err := assertGraphPolicy(r, []candidate{r.Candidate}, blocked, false); err != nil {
		return err
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Repository != "https://example.invalid/selected.git" {
			return fmt.Errorf("wrong selected repository: %s", record.Repository)
		}
	}
	script, err := filepath.Abs(filepath.Join(poetryFixtures, "inspect_install.py"))
	if err != nil {
		return err
	}
	for label, runtime := range map[string]string{"selected": python, "caller": callerPython} {
		command, err := r.Command(label+"-installed", runtime, "-I", script, r.Candidate.Project, r.Candidate.Module)
		if err != nil {
			return err
		}
		var state struct {
			Present, Imported bool
			Version           string
		}
		if err := readJSON(command.Stdout.Path, &state); err != nil {
			return err
		}
		want := runtime == nativePython && !blocked
		if state.Present != want || want && (!state.Imported || state.Version != r.Candidate.Version) {
			return fmt.Errorf("wrong %s installed state: %+v", label, state)
		}
	}
	if !blocked {
		archive, err := poetryDownloadedArchive(r.Env["POETRY_CACHE_DIR"], r.Candidate)
		if err != nil {
			return err
		}
		r.Result.Evidence["selected-artifact"] = archive
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("wrong inspection mode")
	}
	for _, dir := range []string{r.Root, caller.Root} {
		remains, err := filepath.Glob(filepath.Join(dir, ".scfw-poetry-*"))
		if err != nil {
			return err
		}
		if len(remains) != 0 {
			return fmt.Errorf("temporary project remains: %v", remains)
		}
	}
	return assertCleanup(r, string(stderr))
}
