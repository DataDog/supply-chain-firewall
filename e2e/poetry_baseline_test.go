//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestHarnessPoetrySnapshots(t *testing.T) {
	root := t.TempDir()
	before := map[string]string{"pyproject.toml": "original", "poetry.lock": "locked"}
	for name, content := range before {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := poetryProjectSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertPoetryUnchanged(root, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "poetry.lock"), []byte("mutated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := assertPoetryUnchanged(root, snapshot); err == nil {
		t.Fatal("accepted a lock modified by a blocked command")
	}
	if err := os.Remove(filepath.Join(root, "pyproject.toml")); err != nil {
		t.Fatal(err)
	}
	if err := assertPoetryUnchanged(root, snapshot); err == nil {
		t.Fatal("accepted a deleted manifest")
	}
}

func TestHarnessPoetryArchive(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.whl")
	if err := os.WriteFile(path, []byte("archive evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	evidence, err := digestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	selected := candidate{Artifacts: []artifact{{Name: "package.whl", SHA256: evidence.SHA256}}}
	if _, err := poetryDownloadedArchive(root, selected); err != nil {
		t.Fatal(err)
	}
	selected.Artifacts[0].SHA256 = "different"
	if _, err := poetryDownloadedArchive(root, selected); err == nil {
		t.Fatal("accepted archive with mismatching digest")
	}
	selected.Artifacts[0].Name = "missing.whl"
	if _, err := poetryDownloadedArchive(root, selected); err == nil {
		t.Fatal("accepted missing selected archive")
	}
}

type poetryOptions struct {
	operation, proxy              string
	block, errorOnBlock, explicit bool
}

func init() {
	add := func(id, variant, mode string, options poetryOptions) {
		suites["poetry-baseline"] = append(suites["poetry-baseline"], scenario{Scenario: id, Variant: variant, Manager: "poetry", Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "pypi-old", Timeout: 4 * time.Minute, Run: func(r *caseRun) error { return runPoetryBaseline(r, options) }})
	}
	for _, mode := range []string{"resolution", "proxy"} {
		proxy := ""
		if mode == "proxy" {
			proxy = "1"
		}
		add("CORE-01", mode+"-install-allow", mode, poetryOptions{operation: "install", proxy: proxy})
		add("CORE-02", mode+"-install-block-default", mode, poetryOptions{operation: "install", proxy: proxy, block: true})
		add("CORE-02", mode+"-install-block-error", mode, poetryOptions{operation: "install", proxy: proxy, block: true, errorOnBlock: true})
		add("POETRY-01", mode+"-add-allow", mode, poetryOptions{operation: "add", proxy: proxy})
		add("POETRY-01", mode+"-add-block", mode, poetryOptions{operation: "add", proxy: proxy, block: true, errorOnBlock: true})
		add("CORE-12", mode+"-explicit-spaces", mode, poetryOptions{operation: "install", proxy: proxy, explicit: true})
		add("REPORT-01", mode+"-local-allow", mode, poetryOptions{operation: "install", proxy: proxy})
		add("REPORT-01", mode+"-local-block", mode, poetryOptions{operation: "install", proxy: proxy, block: true})
	}
	for _, proxy := range []string{"", "0", "true", "1"} {
		name, mode := proxy, "resolution"
		if name == "" {
			name = "unset"
		}
		if proxy == "1" {
			mode = "proxy"
		}
		add("CORE-10", "proxy-env-"+name, mode, poetryOptions{operation: "install", proxy: proxy, block: true})
	}
	for _, blocked := range []bool{false, true} {
		variant := "proxy-allowed-cleanup"
		if blocked {
			variant = "proxy-blocked-cleanup"
		}
		suites["poetry-baseline"] = append(suites["poetry-baseline"], scenario{Scenario: "LIFE-01", Variant: variant, Manager: "poetry", Mode: "proxy", Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "pypi-old", Timeout: 6 * time.Minute, Run: func(r *caseRun) error {
			if err := runPoetryBaseline(r, poetryOptions{operation: "add", proxy: "1", block: blocked}); err != nil {
				return err
			}
			next := *r
			next.Root = filepath.Join(r.Root, "subsequent")
			env, err := isolatedEnvironment(next.Root)
			if err != nil {
				return err
			}
			next.Env = env
			return runPoetryBaseline(&next, poetryOptions{operation: "install", proxy: "1"})
		}})
	}
	for _, direct := range []struct {
		name string
		args []string
	}{
		{"run", nil}, {"version", []string{"--version"}}, {"global-help", []string{"--help"}},
		{"help", []string{"help", "install"}}, {"list", []string{"list"}}, {"about", []string{"about"}},
		{"install-help", []string{"install", "--help"}}, {"no-command", []string{}},
	} {
		suites["poetry-baseline"] = append(suites["poetry-baseline"], scenario{Scenario: "POETRY-05", Variant: direct.name, Manager: "poetry", Mode: "proxy", Backend: "local", RegistryProfile: "none", Timeout: 2 * time.Minute, Run: func(r *caseRun) error { return runPoetryDirect(r, direct.name, direct.args) }})
	}
}

const poetryFixtures = "testdata/poetry/baseline"

func preparePoetry(r *caseRun, operation string) (string, error) {
	r.WorkDir = filepath.Join(r.Root, "project with spaces")
	if err := os.MkdirAll(r.WorkDir, 0700); err != nil {
		return "", err
	}
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	r.Env["POETRY_VIRTUALENVS_IN_PROJECT"], r.Env["POETRY_KEYRING_ENABLED"] = "true", "false"
	for key, directory := range map[string]string{"POETRY_CONFIG_DIR": "poetry-config", "POETRY_DATA_DIR": "poetry-data", "POETRY_CACHE_DIR": "poetry-bootstrap-cache"} {
		r.Env[key] = filepath.Join(r.Root, directory)
		if err := os.MkdirAll(r.Env[key], 0700); err != nil {
			return "", err
		}
	}
	parts := strings.Split(r.Cell.RuntimeVersion, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid pinned Python version")
	}
	values := map[string]string{"Python": parts[0] + "." + parts[1] + ".*", "Project": "", "Version": ""}
	if operation == "install" {
		values["Project"], values["Version"] = r.Candidate.Project, r.Candidate.Version
	}
	tmpl, err := template.ParseFiles(filepath.Join(poetryFixtures, "pyproject.toml.tmpl"))
	if err != nil {
		return "", err
	}
	var manifest bytes.Buffer
	if err := tmpl.Execute(&manifest, values); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(r.WorkDir, "pyproject.toml"), manifest.Bytes(), 0600); err != nil {
		return "", err
	}
	python := filepath.Join(r.WorkDir, ".venv", "bin", "python")
	if _, err := r.Command("project-venv", r.Cell.Runtime, "-m", "venv", "--without-pip", filepath.Dir(filepath.Dir(python))); err != nil {
		return "", classified("INFRASTRUCTURE_FAILURE", err)
	}
	if operation != "direct" {
		if _, err := r.Command("bootstrap-lock", r.Cell.Executable, "--no-interaction", "lock"); err != nil {
			return "", classified("INFRASTRUCTURE_FAILURE", err)
		}
		for _, argv := range [][]string{{r.Cell.Git, "init", "--quiet"}, {r.Cell.Git, "remote", "add", "origin", "https://example.invalid/scfw-e2e.git"}} {
			if _, err := r.Command("git-bootstrap", argv...); err != nil {
				return "", classified("INFRASTRUCTURE_FAILURE", err)
			}
		}
	}
	// Native lock discovery must not warm the protected artifact download.
	r.Env["POETRY_CACHE_DIR"] = filepath.Join(r.Root, "poetry-install-cache")
	if err := os.MkdirAll(r.Env["POETRY_CACHE_DIR"], 0700); err != nil {
		return "", err
	}
	settings := filepath.Join(r.Root, "poetry-settings.json")
	if err := writeJSON(settings, map[string]string{"project_python": python, "manager": r.Cell.Executable, "poetry_cache": r.Env["POETRY_CACHE_DIR"], "poetry_config": r.Env["POETRY_CONFIG_DIR"]}); err != nil {
		return "", err
	}
	return python, r.Keep("poetry-settings-"+filepath.Base(r.Root), settings)
}

func runPoetryBaseline(r *caseRun, options poetryOptions) error {
	python, err := preparePoetry(r, options.operation)
	if err != nil {
		return err
	}
	before, err := poetryProjectSnapshot(r.WorkDir)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "before", before); err != nil {
		return err
	}
	if options.proxy != "" {
		r.Env["SCFW_PROXY_ENABLED"] = options.proxy
	} else {
		delete(r.Env, "SCFW_PROXY_ENABLED")
	}
	if options.block {
		if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	executable := r.Cell.Executable
	argv := []string{r.Binary, "run"}
	if options.errorOnBlock {
		argv = append(argv, "--error-on-block")
	}
	if options.explicit {
		directory := filepath.Join(r.Root, "manager path with spaces")
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		executable = filepath.Join(directory, "poetry")
		if err := os.Symlink(r.Cell.Executable, executable); err != nil {
			return err
		}
		argv = append(argv, "--executable", executable)
	}
	argv = append(argv, "--", "poetry", "--no-interaction", options.operation)
	if options.operation == "add" {
		argv = append(argv, r.Candidate.Project+"=="+r.Candidate.Version)
	}
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	if command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", commandErr)
	}
	after, err := poetryProjectSnapshot(r.WorkDir)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "after", after); err != nil {
		return err
	}
	wantExit, outcome := 0, "ALLOW"
	if options.block {
		outcome = "BLOCK"
		if options.errorOnBlock || options.proxy == "1" {
			wantExit = 1
		}
		if options.proxy != "1" {
			if err := assertPoetryUnchanged(r.WorkDir, before); err != nil {
				return err
			}
		}
	}
	if !options.block && options.operation == "add" && (before["pyproject.toml"] == after["pyproject.toml"] || before["poetry.lock"] == after["poetry.lock"]) {
		return fmt.Errorf("allowed Poetry add did not update manifest and lock")
	}
	if command.ExitCode != wantExit {
		return fmt.Errorf("SCFW exit=%d, want %d: %v", command.ExitCode, wantExit, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (options.proxy == "1") {
		return fmt.Errorf("SCFW selected the wrong Poetry inspection mode")
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	if err := assertPolicy(records, r.Candidate, "poetry", executable, outcome); err != nil {
		return err
	}
	for _, record := range records {
		if record.Repository != "https://example.invalid/scfw-e2e.git" || !strings.Contains(record.Command, "poetry --no-interaction "+options.operation) {
			return fmt.Errorf("wrong Poetry repository/command record")
		}
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
	if err := r.Keep("policy-"+filepath.Base(r.Root), r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	script, err := filepath.Abs(filepath.Join(poetryFixtures, "inspect_install.py"))
	if err != nil {
		return err
	}
	state, err := r.Command("installed-state", python, "-I", script, r.Candidate.Project, r.Candidate.Module)
	if err != nil {
		return err
	}
	var installed struct {
		Present  bool
		Version  string
		Imported bool
	}
	if err := readJSON(state.Stdout.Path, &installed); err != nil {
		return err
	}
	r.Result.Observations["installed-"+filepath.Base(r.Root)] = installed
	if installed.Present == options.block || (!options.block && (installed.Version != r.Candidate.Version || !installed.Imported)) {
		return fmt.Errorf("unexpected Poetry installed state: %+v", installed)
	}
	if !options.block {
		archive, err := poetryDownloadedArchive(r.Env["POETRY_CACHE_DIR"], r.Candidate)
		if err != nil {
			return err
		}
		r.Result.Evidence["downloaded-wheel-"+filepath.Base(r.Root)] = archive
	}
	leftovers, err := filepath.Glob(filepath.Join(r.Root, ".scfw-poetry-*"))
	if err != nil {
		return err
	}
	if len(leftovers) != 0 {
		return fmt.Errorf("Poetry resolution temporary projects remain: %v", leftovers)
	}
	r.Result.Observations["remaining-poetry-projects-"+filepath.Base(r.Root)] = leftovers
	return assertCleanup(r, string(stderr))
}

func poetryProjectSnapshot(root string) (map[string]string, error) {
	snapshot := map[string]string{}
	for _, name := range []string{"pyproject.toml", "poetry.lock"} {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		snapshot[name] = string(content)
	}
	return snapshot, nil
}

func assertPoetryUnchanged(root string, before map[string]string) error {
	after, err := poetryProjectSnapshot(root)
	if err != nil {
		return err
	}
	if !maps.Equal(before, after) {
		return fmt.Errorf("resolution BLOCK changed Poetry project or lock")
	}
	return nil
}

func retainPoetrySnapshot(r *caseRun, phase string, snapshot map[string]string) error {
	path := filepath.Join(r.Root, "project-"+phase+".json")
	if err := writeJSON(path, snapshot); err != nil {
		return err
	}
	return r.Keep("project-"+phase+"-"+filepath.Base(r.Root), path)
}

func poetryDownloadedArchive(cache string, selected candidate) (fileEvidence, error) {
	var found fileEvidence
	err := filepath.WalkDir(cache, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		for _, artifact := range selected.Artifacts {
			if entry.Name() != artifact.Name {
				continue
			}
			evidence, err := digestFile(path)
			if err != nil {
				return err
			}
			if evidence.SHA256 != artifact.SHA256 {
				return fmt.Errorf("Poetry cached archive differs from registry discovery: %s", path)
			}
			found = evidence
		}
		return nil
	})
	if err != nil {
		return fileEvidence{}, err
	}
	if found.Path == "" {
		return fileEvidence{}, fmt.Errorf("selected public wheel absent from fresh Poetry artifact cache")
	}
	return found, nil
}

func runPoetryDirect(r *caseRun, name string, arguments []string) error {
	python, err := preparePoetry(r, "direct")
	if err != nil {
		return err
	}
	r.Env["SCFW_PROXY_ENABLED"] = "1"
	r.Env["https_proxy"] = "http://invalid:port"
	r.Env["REQUESTS_CA_BUNDLE"] = filepath.Join(r.Root, "missing-ca.pem")
	r.Env["SCFW_E2E_POETRY_PROBE"] = "literal environment value with spaces"
	input, expectedExit := "", 0
	if name == "run" {
		probe, err := filepath.Abs(filepath.Join(poetryFixtures, "direct_probe.py"))
		if err != nil {
			return err
		}
		arguments = []string{"run", python, "-I", probe, "install", "argument with spaces", "--help"}
		input, expectedExit = "Poetry stdin probe\n", 7
	}
	native, err := r.CommandInput("native-direct", input, append([]string{r.Cell.Executable}, arguments...)...)
	if native.TimedOut {
		return err
	}
	if native.ExitCode != expectedExit {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("native Poetry direct command exit=%d, want %d: %v", native.ExitCode, expectedExit, err))
	}
	argv := append([]string{r.Binary, "run", "--executable", r.Cell.Executable, "--", "poetry"}, arguments...)
	command, commandErr := r.CommandInput("scfw-direct", input, argv...)
	if command.TimedOut {
		return commandErr
	}
	if command.ExitCode != expectedExit {
		return fmt.Errorf("SCFW changed direct command exit: got %d, want %d: %v", command.ExitCode, expectedExit, commandErr)
	}
	want, err := os.ReadFile(native.Stdout.Path)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(command.Stdout.Path)
	if err != nil {
		return err
	}
	if len(got) == 0 || !bytes.Equal(got, want) {
		return fmt.Errorf("SCFW changed native Poetry stdout/child stdin, arguments, or environment")
	}
	nativeStderr, err := os.ReadFile(native.Stderr.Path)
	if err != nil {
		return err
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if !bytes.Contains(stderr, nativeStderr) || strings.Contains(string(stderr), "started package manager proxy") {
		return fmt.Errorf("direct command lost stderr or acquired a proxy")
	}
	if _, err := os.Stat(r.Env["SCFW_LOG_FILE"]); !os.IsNotExist(err) {
		return fmt.Errorf("direct Poetry command produced a policy report or report lookup failed: %v", err)
	}
	temporary, err := filepath.Glob(filepath.Join(r.Env["TMPDIR"], "scfw-*"))
	if err != nil {
		return err
	}
	if len(temporary) != 0 {
		return fmt.Errorf("direct Poetry command left invocation material: %v", temporary)
	}
	r.Result.ResolvedAction = "DIRECT"
	r.Result.Observations["native_child_exit"] = expectedExit
	r.Result.Observations["policy_report_absent"] = true
	r.Result.Observations["remaining_scfw_temporary_paths"] = temporary
	return nil
}
