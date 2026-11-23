//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
)

func runLocalPolicy(r *caseRun, options localPolicyOptions) error {
	args, inspect, err := prepareLocalPolicyInstall(r)
	if err != nil {
		return err
	}
	before, err := localPolicySnapshot(r.WorkDir)
	if err != nil {
		return err
	}
	if err := retainPoetrySnapshot(r, "before", before); err != nil {
		return err
	}
	if err := writeLocalPolicyLists(r, options.lists); err != nil {
		return err
	}
	delete(r.Env, "SCFW_PROXY_ENABLED")
	delete(r.Env, "SCFW_ON_WARNING")
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	if options.environment != "" {
		r.Env["SCFW_ON_WARNING"] = options.environment
	}
	r.Result.Observations["warning-settings"] = map[string]any{"flag": options.flag, "environment": options.environment, "stdin": "non-TTY"}
	if options.reportFailure {
		// A regular file cannot become a parent directory, even for root.
		parent := filepath.Join(r.Root, "report-parent-file")
		if err := os.WriteFile(parent, []byte("preserve this file\n"), 0600); err != nil {
			return err
		}
		r.Env["SCFW_LOG_FILE"] = filepath.Join(parent, "report.jsonl")
	}
	argv := []string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable}
	if options.flag != "" {
		argv = append(argv, options.flag)
	}
	argv = append(append(argv, "--"), args...)
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	blocked := options.outcome == "BLOCK" || (options.outcome == "WARN" && r.Spec.Mode == "resolution" && !options.allowWarning)
	action, expectedExit := "ALLOW", 0
	if blocked {
		action, expectedExit = "BLOCK", 1
		if r.Cell.Manager == "uv" {
			expectedExit = 2
		}
	}
	if command.ExitCode != expectedExit || command.Signal != "" {
		return fmt.Errorf("SCFW exit=%d signal=%q, want %d: %v", command.ExitCode, command.Signal, expectedExit, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") || strings.Contains(string(stderr), "Proceed with installation?") {
		return fmt.Errorf("incorrect inspection mode or unexpected interactive prompt")
	}
	if strings.Contains(string(stderr), "Failed to import findings list") != options.invalid {
		return fmt.Errorf("unexpected findings-list import diagnostic")
	}
	if options.reportFailure {
		diagnostic := "failed to report firewall outcome"
		if r.Spec.Mode == "proxy" {
			diagnostic = "failed to report proxy firewall outcome"
		}
		if !strings.Contains(string(stderr), diagnostic) {
			return fmt.Errorf("missing report failure diagnostic")
		}
		data, err := os.ReadFile(filepath.Dir(r.Env["SCFW_LOG_FILE"]))
		if err != nil || string(data) != "preserve this file\n" {
			return fmt.Errorf("report failure changed its blocking file: %v", err)
		}
		if blocked {
			if !strings.Contains(string(stderr), "Policy evaluation outcome: BLOCK") || !strings.Contains(string(stderr), "FindingsListVerifier [CRITICAL]: SCFW E2E exact-critical") {
				return fmt.Errorf("missing explicit list BLOCK diagnostic when reporting fails")
			}
		}
		r.Result.PolicyOutcome = "NOT_OBSERVED"
		r.Result.Observations["expected-policy"] = options.outcome
	} else {
		records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
		if err != nil {
			return err
		}
		if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
			return err
		}
		if err := assertLocalPolicy(records, r.Candidate, r.Cell, options, action, strings.Join(args, " ")); err != nil {
			return err
		}
		r.Result.PolicyOutcome = options.outcome
	}
	r.Result.ResolvedAction = action
	if options.outcome != "ALLOW" && !strings.Contains(string(stderr), r.Candidate.Project) {
		return fmt.Errorf("policy explanation does not identify the package")
	}
	if err := inspect(blocked); err != nil {
		return err
	}
	after, err := localPolicySnapshot(r.WorkDir)
	if err != nil {
		return err
	}
	if blocked && r.Spec.Mode == "resolution" && !reflect.DeepEqual(before, after) {
		return fmt.Errorf("resolution denial changed the project or lockfile")
	}
	if err := retainPoetrySnapshot(r, "after", after); err != nil {
		return err
	}
	return assertCleanup(r, string(stderr))
}

func writeLocalPolicyLists(r *caseRun, names []string) error {
	tmpl, err := template.ParseFiles("testdata/local_policy/findings.yaml.tmpl")
	if err != nil {
		return err
	}
	for index, name := range names {
		var data bytes.Buffer
		if name == "malformed" {
			content, err := os.ReadFile("testdata/local_policy/malformed.yaml")
			if err != nil {
				return err
			}
			data.Write(content)
		} else {
			values := map[string]string{"Ecosystem": r.Candidate.Ecosystem, "Project": r.Candidate.Project, "Version": r.Candidate.Version}
			if name == "case-insensitive" {
				values["Ecosystem"] = strings.ToLower(values["Ecosystem"])
			}
			if err := tmpl.ExecuteTemplate(&data, name, values); err != nil {
				return err
			}
		}
		extension := []string{".yml", ".yaml"}[index%2]
		path := filepath.Join(r.Env["SCFW_HOME"], "list_verifier", name+extension)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
			return err
		}
		if err := r.Keep("list-"+name, path); err != nil {
			return err
		}
	}
	return nil
}

func assertLocalPolicy(records []policyRecord, c candidate, cell cell, options localPolicyOptions, action, command string) error {
	found := false
	for _, record := range records {
		if record.Manager != cell.Manager || record.Executable != cell.Executable || record.Timestamp.IsZero() || record.Outcome != action || record.Command != command {
			return fmt.Errorf("incorrect local policy identity or resolved action: %+v", record)
		}
		for _, pkg := range record.Packages {
			if !strings.EqualFold(pkg.Ecosystem, c.Ecosystem) || pkg.Name != c.Project || pkg.Version != c.Version {
				continue
			}
			found = true
			if pkg.Outcome != options.outcome {
				return fmt.Errorf("package outcome %s, want %s", pkg.Outcome, options.outcome)
			}
			actual := map[string]string{}
			for _, finding := range pkg.Findings {
				if finding.Verifier == "FindingsListVerifier" {
					key := strings.TrimPrefix(finding.Text, "SCFW E2E ")
					if _, duplicate := actual[key]; duplicate {
						return fmt.Errorf("duplicate list finding %s", key)
					}
					actual[key] = finding.Severity
				}
			}
			if len(actual) != len(options.findings) || (len(actual) != 0 && !reflect.DeepEqual(actual, options.findings)) {
				return fmt.Errorf("list findings %v, want %v; complete evidence: %+v", actual, options.findings, pkg)
			}
		}
	}
	if !found {
		return fmt.Errorf("missing exact package identity in local policy report")
	}
	return nil
}

func prepareLocalPolicyInstall(r *caseRun) ([]string, func(bool) error, error) {
	c := r.Candidate
	if r.Cell.Manager == "npm" {
		if _, err := prepareNPMProject(r); err != nil {
			return nil, nil, err
		}
		return []string{"npm", "install", c.Project + "@" + c.Version, "--ignore-scripts", "--no-audit", "--no-fund"}, func(blocked bool) error { return assertNPMInstall(r, blocked) }, nil
	}
	python, target := "", ""
	var args []string
	switch r.Cell.Manager {
	case "poetry":
		var err error
		python, err = preparePoetry(r, "install")
		if err != nil {
			return nil, nil, err
		}
		args = []string{"poetry", "--no-interaction", "install"}
	case "pip", "uv":
		r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
		venv := filepath.Join(r.Root, "venv")
		if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
			return nil, nil, classified("INFRASTRUCTURE_FAILURE", err)
		}
		python = filepath.Join(venv, "bin", "python")
		if r.Cell.Manager == "pip" {
			target = filepath.Join(r.Root, "installed packages")
			args = []string{"pip", "install", "--no-deps", "--only-binary=:all:", "--ignore-installed", "--target", target, "--report", filepath.Join(r.Root, "pip-install.json"), c.Project + "==" + c.Version}
		} else {
			if _, _, err := prepareUV(r, uvOptions{}); err != nil {
				return nil, nil, err
			}
			args = []string{"uv", "pip", "install", "--python", python, "--no-deps", "--only-binary=:all:", c.Project + "==" + c.Version}
		}
	default:
		return nil, nil, fmt.Errorf("unsupported local policy manager %s", r.Cell.Manager)
	}
	inspect := func(blocked bool) error {
		script := "testdata/poetry/baseline/inspect_install.py"
		arguments := []string{c.Project, c.Module}
		if target != "" {
			script = "testdata/pip_baseline/inspect_install.py"
			arguments = append([]string{target}, arguments...)
		}
		script, err := filepath.Abs(script)
		if err != nil {
			return err
		}
		observation, err := r.Command("installed-state", append([]string{python, "-I", script}, arguments...)...)
		if err != nil {
			return err
		}
		var state struct {
			Present, Imported bool
			Version           string
		}
		if err := readJSON(observation.Stdout.Path, &state); err != nil {
			return err
		}
		r.Result.Observations["installed"] = state
		if state.Present == blocked || (!blocked && (state.Version != c.Version || !state.Imported)) {
			return fmt.Errorf("unexpected installed state: %+v", state)
		}
		if !blocked && r.Cell.Manager == "poetry" {
			archive, err := poetryDownloadedArchive(r.Env["POETRY_CACHE_DIR"], c)
			if err != nil {
				return err
			}
			r.Result.Evidence["downloaded-wheel"] = archive
		}
		return nil
	}
	return args, inspect, nil
}

func localPolicySnapshot(root string) (map[string]string, error) {
	files := map[string]string{}
	for _, name := range []string{"package.json", "package-lock.json", "pyproject.toml", "poetry.lock"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files[name] = string(data)
	}
	return files, nil
}
