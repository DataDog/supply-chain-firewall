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
	"testing"
	"time"
)

type pypiAgeOptions struct {
	name, minimum, flag            string
	warning, invalid, errorOnBlock bool
}

func init() {
	variants := []pypiAgeOptions{
		{name: "recent-default", warning: true},
		{name: "recent-allow-warning", warning: true, flag: "--allow-on-warning", errorOnBlock: true},
		{name: "recent-block-warning", warning: true, flag: "--block-on-warning", errorOnBlock: true},
		{name: "old-default"},
		{name: "recent-disabled", minimum: "0"},
		{name: "recent-explicit24h", minimum: "24", warning: true, errorOnBlock: true},
		{name: "recent-invalid-negative", minimum: "-1", warning: true, invalid: true, errorOnBlock: true},
		{name: "recent-invalid-noninteger", minimum: "invalid", warning: true, invalid: true, errorOnBlock: true},
	}
	for _, manager := range []string{"pip", "poetry", "uv"} {
		modes := []string{"resolution", "proxy"}
		if manager == "uv" {
			modes = []string{"proxy"}
		}
		for _, mode := range modes {
			for _, options := range variants {
				key := "pypi-recent"
				if options.name == "old-default" {
					key = "pypi-old"
				}
				suites["pypi-recent"] = append(suites["pypi-recent"], scenario{Scenario: "LOCAL-03", Variant: manager + "-" + mode + "-" + options.name, Manager: manager, Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: key, Timeout: 4 * time.Minute, Run: func(r *caseRun) error { return runPyPIAge(r, options) }})
			}
		}
	}
}

func preparePyPIAge(r *caseRun) (string, []string, error) {
	c := r.Candidate
	if r.Cell.Manager == "poetry" {
		python, err := preparePoetry(r, "install")
		return python, []string{"poetry", "--no-interaction", "install"}, err
	}
	if r.Cell.Manager == "uv" {
		if _, _, err := prepareUV(r, uvOptions{flag: "1"}); err != nil {
			return "", nil, err
		}
	}
	venv := filepath.Join(r.Root, "venv")
	if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
		return "", nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	python := filepath.Join(venv, "bin", "python")
	if r.Cell.Manager == "uv" {
		return python, []string{"uv", "--verbose", "pip", "install", "--python", python, "--no-deps", "--only-binary=:all:", c.Project + "==" + c.Version}, nil
	}
	parts := strings.Split(r.Cell.RuntimeVersion, ".")
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("invalid Python pin")
	}
	target := filepath.Join(venv, "lib", "python"+strings.Join(parts[:2], "."), "site-packages")
	return python, []string{"pip", "install", "--no-deps", "--only-binary=:all:", "--ignore-installed", "--target", target, "--report", filepath.Join(r.Root, "pip-install.json"), c.Project + "==" + c.Version}, nil
}

func runPyPIAge(r *caseRun, options pypiAgeOptions) error {
	c := r.Candidate
	recent := r.Spec.DiscoveryKey == "pypi-recent"
	if recent {
		if err := validatePyPIRecentCell(c, r.Cell, time.Now().UTC()); err != nil {
			return err
		}
	} else {
		for _, a := range c.Artifacts {
			if a.UploadedAt.After(time.Now().UTC().Add(-48 * time.Hour)) {
				return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("old control is not older than48h"))
			}
		}
	}
	python, args, err := preparePyPIAge(r)
	if err != nil {
		return err
	}
	delete(r.Env, "SCFW_PACKAGE_MINIMUM_AGE")
	delete(r.Env, "SCFW_PROXY_ENABLED")
	if options.minimum != "" {
		r.Env["SCFW_PACKAGE_MINIMUM_AGE"] = options.minimum
	}
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	r.Result.Observations["minimum_age"] = map[string]any{"environment_set": options.minimum != "", "value": options.minimum, "default_hours": 24}
	r.Result.Observations["publication"] = c.Artifacts
	if _, err := os.Stat(filepath.Join(r.Env["SCFW_HOME"], "list_verifier")); !os.IsNotExist(err) {
		return fmt.Errorf("age case requires absent findings lists: %v", err)
	}
	var before map[string]string
	if r.Cell.Manager == "poetry" {
		before, err = poetryProjectSnapshot(r.WorkDir)
		if err != nil {
			return err
		}
		if err := retainPoetrySnapshot(r, "before", before); err != nil {
			return err
		}
	}
	argv := []string{r.Binary, "run", "--executable", r.Cell.Executable}
	if options.flag != "" {
		argv = append(argv, options.flag)
	}
	if options.errorOnBlock {
		argv = append(argv, "--error-on-block")
	}
	argv = append(append(argv, "--"), args...)
	if recent {
		if err := validatePyPIRecentCell(c, r.Cell, time.Now().UTC()); err != nil {
			return err
		}
		if err := checkPyPIRecentInterval(c, time.Now().UTC(), time.Now().UTC().Add(r.Spec.Timeout)); err != nil {
			return err
		}
	}
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	if recent {
		if err := checkPyPIRecentInterval(c, command.StartedAt, command.EndedAt); err != nil {
			return err
		}
	}
	blocked := options.warning && r.Spec.Mode == "resolution" && options.flag != "--allow-on-warning"
	expectedExit := 0
	if blocked && options.errorOnBlock {
		expectedExit = 1
	}
	if command.ExitCode != expectedExit || command.Signal != "" {
		return fmt.Errorf("SCFW exit %d signal %q; want %d: %v", command.ExitCode, command.Signal, expectedExit, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") || strings.Contains(string(stderr), "falling back to dry-run resolution") {
		return fmt.Errorf("incorrect Python inspection mode")
	}
	if strings.Contains(string(stderr), "Invalid minimum package age; using default") != options.invalid {
		return fmt.Errorf("incorrect invalid-age fallback diagnostic")
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	policy, action := "ALLOW", "ALLOW"
	if options.warning {
		policy = "WARN"
	}
	if blocked {
		action = "BLOCK"
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = policy, action
	if r.Spec.Mode == "resolution" && len(records) != 1 {
		return fmt.Errorf("resolution produced %d records, want1", len(records))
	}
	if err := assertPyPIAgePolicy(records, c, r.Cell, policy, action); err != nil {
		return err
	}
	expectedVersion := c.Version
	if blocked {
		expectedVersion = ""
	}
	if err := assertUVInstalled(r, python, expectedVersion, "installed"); err != nil {
		return err
	}
	if r.Cell.Manager == "poetry" {
		if err := assertPoetryUnchanged(r.WorkDir, before); err != nil {
			return err
		}
		after, err := poetryProjectSnapshot(r.WorkDir)
		if err != nil {
			return err
		}
		if err := retainPoetrySnapshot(r, "after", after); err != nil {
			return err
		}
		if !blocked {
			a, err := poetryDownloadedArchive(r.Env["POETRY_CACHE_DIR"], c)
			if err != nil {
				return err
			}
			r.Result.Evidence["downloaded-wheel"] = a
		}
		leftovers, err := filepath.Glob(filepath.Join(r.Root, ".scfw-poetry-*"))
		if err != nil {
			return err
		}
		if len(leftovers) != 0 {
			return fmt.Errorf("Poetry inspection left temporary projects: %v", leftovers)
		}
	}
	if r.Cell.Manager == "pip" && !blocked {
		report := filepath.Join(r.Root, "pip-install.json")
		var data pipGraphReport
		if err := readJSON(report, &data); err != nil {
			return err
		}
		if err := matchPipInputReport(data, []candidate{c}); err != nil {
			return err
		}
		if err := r.Keep("installed-artifact", report); err != nil {
			return err
		}
	}
	if r.Cell.Manager == "uv" && !strings.Contains(string(stderr), c.Artifacts[0].Name) {
		return fmt.Errorf("uv verbose output lacks discovered wheel identity %s", c.Artifacts[0].Name)
	}
	return assertCleanup(r, string(stderr))
}

func assertPyPIAgePolicy(records []policyRecord, c candidate, current cell, outcome, action string) error {
	if len(records) == 0 {
		return fmt.Errorf("missing age policy records")
	}
	for _, record := range records {
		if record.Manager != current.Manager || record.Executable != current.Executable || record.Timestamp.IsZero() || record.Outcome != action || len(record.Packages) != 1 {
			return fmt.Errorf("unexpected age report identity/action: %+v", record)
		}
		pkg := record.Packages[0]
		normalize := func(name string) string {
			return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
		}
		if !strings.EqualFold(pkg.Ecosystem, "pypi") || normalize(pkg.Name) != normalize(c.Project) || pkg.Version != c.Version || pkg.Outcome != outcome {
			return fmt.Errorf("wrong exact age policy: %+v", pkg)
		}
		if len(pkg.Failures) != 0 {
			return fmt.Errorf("live verifier failures remain visible: %s", pkg.Failures)
		}
		count := 0
		if outcome == "WARN" {
			count = 1
		}
		if len(pkg.Findings) != count {
			return fmt.Errorf("expected %d isolated age findings; got %+v", count, pkg.Findings)
		}
		for _, finding := range pkg.Findings {
			if finding.Verifier != "PackageAgeVerifier" || finding.Severity != "WARNING" || !strings.Contains(finding.Text, pkg.Name+"@"+c.Version) || !strings.Contains(finding.Text, "less than 24 hours ago") {
				return fmt.Errorf("warning is not the default24h age finding: %+v", finding)
			}
		}
	}
	return nil
}

func TestHarnessPyPIAgePolicy(t *testing.T) {
	var fixtures map[string][]policyRecord
	if err := readJSON("testdata/age_pypi/policy.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	c := candidate{Project: "fixture-leaf", Version: "1.0.0"}
	for _, manager := range []string{"pip", "poetry", "uv"} {
		for _, action := range []string{"ALLOW", "BLOCK"} {
			records := fixtures["warning"]
			records[0].Manager = manager
			records[0].Executable = "/manager"
			records[0].Outcome = action
			if err := assertPyPIAgePolicy(records, c, cell{Manager: manager, Executable: "/manager"}, "WARN", action); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"list", "wrong-version", "other-finding", "wrong-threshold", "failure"} {
		if err := assertPyPIAgePolicy(fixtures[name], c, cell{Manager: "pip", Executable: "/manager"}, "WARN", "ALLOW"); err == nil {
			t.Errorf("accepted %s as age evidence", name)
		}
	}
	if err := assertPyPIAgePolicy(fixtures["allowed"], c, cell{Manager: "pip", Executable: "/manager"}, "ALLOW", "ALLOW"); err != nil {
		t.Fatal(err)
	}
}
