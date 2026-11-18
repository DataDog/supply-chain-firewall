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
	"strings"
	"text/template"
	"time"
)

func init() {
	add := func(id, variant, mode, key string, caps []string, run func(*caseRun) error) {
		suites["pip-config-lifecycle"] = append(suites["pip-config-lifecycle"], scenario{Scenario: id, Variant: mode + "-" + variant, Manager: "pip", Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: key, Capabilities: caps, Timeout: 5 * time.Minute, Run: run})
	}
	for _, mode := range []string{"resolution", "proxy"} {
		for _, variant := range []string{"command-section", "environment-precedence", "flag-precedence", "python-flag", "python-environment", "shell-shim", "global-values", "global-abbreviations"} {
			for _, blocked := range []bool{false, true} {
				action := "allow"
				if blocked {
					action = "block"
				}
				caps := []string{"pip-resolution-report"}
				if strings.HasPrefix(variant, "python-") {
					caps = append(caps, "pip-python-option")
				}
				add("PIP-03", variant+"-"+action, mode, "pypi-old", caps, func(r *caseRun) error { return runPipConfiguration(r, variant, blocked) })
			}
		}
		add("PIP-04", "dry-run-with-finding", mode, "pypi-old", []string{"pip-resolution-report"}, runPipDryRun)
		for _, variant := range []string{"unavailable-version", "install-filesystem-error"} {
			add("CORE-14", variant, mode, "pypi-old", []string{"pip-resolution-report"}, func(r *caseRun) error { return runPipNativeFailure(r, variant) })
		}
	}
	for _, blocked := range []bool{false, true} {
		name := "upgrade-allow"
		if blocked {
			name = "existing-venv-block"
		}
		add("PIP-04", name, "resolution", "pip-graph", []string{"pip-resolution-report"}, func(r *caseRun) error { return runPipVenvUpgrade(r, blocked) })
	}
	for _, variant := range []string{"guarded-install", "informational", "proxy-allow", "proxy-block"} {
		mode := "resolution"
		if strings.HasPrefix(variant, "proxy-") {
			mode = "proxy"
		}
		add("CORE-11", "below-22.2-"+variant, mode, "pypi-old", []string{"pip-below-resolution-minimum"}, func(r *caseRun) error { return runPipVersionBoundary(r, variant) })
	}
}
func preparePipInvocation(r *caseRun) error {
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	_, err := r.Command("git-init", r.Cell.Git, "init", "--quiet")
	return err
}
func pipConfigurationFixture(r *caseRun, name, path string, values map[string]string) error {
	t, err := template.ParseFiles(filepath.Join("testdata/pip_inputs/configuration", name))
	if err != nil {
		return err
	}
	var data bytes.Buffer
	if err := t.Execute(&data, values); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, data.Bytes(), 0700); err != nil {
		return err
	}
	return r.Keep(name, path)
}
func pipSCFWCommand(r *caseRun, label string, args []string) (commandEvidence, error) {
	prefix := []string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", "pip"}
	return r.Command(label, append(prefix, args...)...)
}
func checkPipInvocation(r *caseRun, ev commandEvidence, commandErr error, blocked, noTargets bool, nodes []candidate) error {
	if ev.TimedOut || ev.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if (ev.ExitCode != 0) != blocked {
		return fmt.Errorf("pip exit=%d blocked=%t: %v", ev.ExitCode, blocked, commandErr)
	}
	stderr, err := os.ReadFile(ev.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("incorrect pip inspection mode")
	}
	if err := assertGraphPolicy(r, nodes, blocked, noTargets); err != nil {
		return err
	}
	return assertCleanup(r, string(stderr))
}
func runPipConfiguration(r *caseRun, variant string, blocked bool) error {
	if err := preparePipInvocation(r); err != nil {
		return err
	}
	target, report := filepath.Join(r.Root, "installed packages"), filepath.Join(r.Root, "report.json")
	args := []string{}
	values := map[string]string{"Global": "https://pypi.org/scfw-e2e-missing-global-index/", "Install": "https://pypi.org/scfw-e2e-missing-command-index/"}
	var unchanged []fileEvidence
	switch variant {
	case "command-section", "environment-precedence", "flag-precedence":
		path := filepath.Join(r.Root, "config with spaces", "pip.conf")
		if variant == "command-section" {
			values["Install"] = "https://pypi.org/simple"
			delete(r.Env, "PIP_INDEX_URL")
		}
		if variant == "flag-precedence" {
			r.Env["PIP_INDEX_URL"] = "https://pypi.org/scfw-e2e-missing-env-index/"
		}
		if err := pipConfigurationFixture(r, "pip.conf.tmpl", path, values); err != nil {
			return err
		}
		r.Env["PIP_CONFIG_FILE"] = path
		unchanged = append(unchanged, r.Result.Evidence["pip.conf.tmpl"])
	case "python-flag", "python-environment":
		venv := filepath.Join(r.Root, "selected interpreter with spaces")
		if _, err := r.Command("selected-venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
			return err
		}
		python := filepath.Join(venv, "bin", "python")
		version, err := r.Command("selected-python-version", python, "--version")
		if err != nil {
			return err
		}
		versionText, err := os.ReadFile(version.Stdout.Path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(versionText)) != "Python "+r.Cell.RuntimeVersion {
			return fmt.Errorf("selected interpreter version differs from pin")
		}
		if variant == "python-flag" {
			args = append(args, "--python", python)
		} else {
			r.Env["PIP_PYTHON"] = python
		}
		r.Result.Observations["selected_python"] = python
		path := filepath.Join(venv, "pip.conf")
		values["Install"] = "https://pypi.org/simple"
		if err := pipConfigurationFixture(r, "pip.conf.tmpl", path, values); err != nil {
			return err
		}
		delete(r.Env, "PIP_INDEX_URL")
		// An existing empty config keeps unrelated user config disabled while allowing
		// the selected interpreter's own pip.conf to participate.
		empty := filepath.Join(r.Root, "empty.conf")
		if err := os.WriteFile(empty, nil, 0600); err != nil {
			return err
		}
		r.Env["PIP_CONFIG_FILE"] = empty
		target = filepath.Join(venv, "lib", "python"+strings.Join(strings.Split(r.Cell.RuntimeVersion, ".")[:2], "."), "site-packages")
		unchanged = append(unchanged, r.Result.Evidence["pip.conf.tmpl"])
	case "shell-shim":
		path := filepath.Join(r.Root, "launcher with spaces", "pip")
		quoted := "'" + strings.ReplaceAll(r.Cell.Executable, "'", "'\\''") + "'"
		if err := pipConfigurationFixture(r, "pip-shim.sh.tmpl", path, map[string]string{"Executable": quoted}); err != nil {
			return err
		}
		r.Cell.Executable = path
		unchanged = append(unchanged, r.Result.Evidence["pip-shim.sh.tmpl"])
		ev, err := r.Command("shim-diagnostics", path, "debug", "--disable-pip-version-check")
		if err != nil {
			return err
		}
		output, err := os.ReadFile(ev.Stdout.Path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(output), "sys.executable: "+filepath.Join(filepath.Dir(r.Result.Cell.Executable), "python")) {
			return fmt.Errorf("shell shim changed pinned interpreter")
		}
	case "global-values", "global-abbreviations":
		log := filepath.Join(r.Root, "help")
		if variant == "global-values" {
			args = append(args, "--log", log, "--timeout", "20")
		} else {
			args = append(args, "--log-f", log, "--time", "20")
		}
		r.Result.Observations["value_is_not_command"] = log
	}
	args = append(args, "install", "--no-cache-dir", "--no-deps", "--only-binary=:all:", "--report", report)
	if !strings.HasPrefix(variant, "python-") {
		args = append(args, "--target", target)
	}
	if variant == "flag-precedence" {
		args = append(args, "--index-url", "https://pypi.org/simple")
	}
	args = append(args, r.Candidate.Project+"=="+r.Candidate.Version)
	r.Result.Observations["pip_configuration_environment"] = map[string]string{"PIP_INDEX_URL": r.Env["PIP_INDEX_URL"], "PIP_PYTHON": r.Env["PIP_PYTHON"]}
	if blocked {
		if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	ev, err := pipSCFWCommand(r, "scfw", args)
	if err := checkPipInvocation(r, ev, err, blocked, false, []candidate{r.Candidate}); err != nil {
		return err
	}
	if err := assertPipInputInstalled(r, target, r.Candidate, !blocked); err != nil {
		return err
	}
	if !blocked {
		var actual pipGraphReport
		if err := readJSON(report, &actual); err != nil {
			return err
		}
		if err := matchPipInputReport(actual, []candidate{r.Candidate}); err != nil {
			return err
		}
		if err := r.Keep("install-report", report); err != nil {
			return err
		}
	}
	for _, evidence := range unchanged {
		if err := verifyGraphFile(evidence); err != nil {
			return fmt.Errorf("pip input changed: %w", err)
		}
	}
	return nil
}
func runPipDryRun(r *caseRun) error {
	if err := preparePipInvocation(r); err != nil {
		return err
	}
	if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
		return err
	}
	target, report := filepath.Join(r.Root, "installed"), filepath.Join(r.Root, "report.json")
	args := []string{"install", "--dry-run", "--no-cache-dir", "--no-deps", "--target", target, "--report", report, r.Candidate.Artifacts[0].URL + "#sha256=" + r.Candidate.Artifacts[0].SHA256}
	blocked := r.Spec.Mode == "proxy"
	ev, err := pipSCFWCommand(r, "scfw", args)
	if err := checkPipInvocation(r, ev, err, blocked, !blocked, []candidate{r.Candidate}); err != nil {
		return err
	}
	if err := assertPipInputInstalled(r, target, r.Candidate, false); err != nil {
		return err
	}
	if !blocked {
		var actual pipGraphReport
		if err := readJSON(report, &actual); err != nil {
			return err
		}
		if err := matchPipInputReport(actual, []candidate{r.Candidate}); err != nil {
			return err
		}
		if err := r.Keep("dry-run-report", report); err != nil {
			return err
		}
	}
	r.Result.Observations["dry_run_boundary"] = "Resolution skips dry-run evaluation; proxy evaluates the explicitly downloaded public wheel even when no install is requested."
	return nil
}
func runPipNativeFailure(r *caseRun, variant string) error {
	if err := preparePipInvocation(r); err != nil {
		return err
	}
	target := filepath.Join(r.Root, "target")
	args := []string{"install", "--no-cache-dir", "--no-deps", "--only-binary=:all:", "--ignore-installed"}
	diagnostic := "No matching distribution found"
	if variant == "unavailable-version" {
		args = append(args, "--target", target, r.Candidate.Project+"==999999999.0")
	} else {
		if err := os.WriteFile(target, []byte("preserve this file\n"), 0600); err != nil {
			return err
		}
		args = append(args, "--prefix", target, r.Candidate.Project+"=="+r.Candidate.Version)
		diagnostic = "Not a directory"
	}
	native, nativeErr := r.Command("native-failure", append([]string{r.Cell.Executable}, args...)...)
	if native.TimedOut || native.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("native launch: %v", nativeErr))
	}
	if native.ExitCode == 0 {
		return fmt.Errorf("native failure prerequisite: %v", nativeErr)
	}
	nativeText, err := os.ReadFile(native.Stderr.Path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(nativeText), diagnostic) {
		return fmt.Errorf("native failure lacks expected diagnostic %q", diagnostic)
	}
	ev, commandErr := pipSCFWCommand(r, "scfw", args)
	if ev.TimedOut || ev.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if ev.ExitCode != native.ExitCode {
		return fmt.Errorf("native exit%d differs from SCFW exit%d", native.ExitCode, ev.ExitCode)
	}
	text, err := os.ReadFile(ev.Stderr.Path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(text), diagnostic) {
		return fmt.Errorf("SCFW lost native diagnostic")
	}
	if err := assertGraphPolicy(r, []candidate{r.Candidate}, false, variant == "unavailable-version"); err != nil {
		return err
	}
	if variant == "install-filesystem-error" {
		body, err := os.ReadFile(target)
		if err != nil || string(body) != "preserve this file\n" {
			return fmt.Errorf("native failing install replaced target file: %v", err)
		}
	}
	r.Result.Observations["native_exit"] = native.ExitCode
	r.Result.Observations["failure_stage"] = variant
	return assertCleanup(r, string(text))
}
func runPipVenvUpgrade(r *caseRun, blocked bool) error {
	graph, err := loadPipGraph(r.Candidate)
	if err != nil {
		return err
	}
	if graph.Cell.ID != r.Cell.ID || graph.Cell.ManagerVersion != r.Cell.ManagerVersion || graph.Cell.Executable != r.Cell.Executable || graph.Cell.RuntimeVersion != r.Cell.RuntimeVersion || graph.Cell.Runtime != r.Cell.Runtime {
		return fmt.Errorf("graph belongs to another cell")
	}
	if err := preparePipInvocation(r); err != nil {
		return err
	}
	if err := preparePipSatisfied(r); err != nil {
		return err
	}
	current, previous, leaf := graph.Roots[0], graph.Roots[1], graph.Leaves[0]
	if _, err := r.Command("prime-existing-venv", r.Cell.Executable, "install", "--no-cache-dir", "--only-binary=:all:", previous.Project+"=="+previous.Version, leaf.Project+"=="+leaf.Version); err != nil {
		return err
	}
	target := filepath.Join(r.Root, "venv", "lib", "python"+strings.Join(strings.Split(r.Cell.RuntimeVersion, ".")[:2], "."), "site-packages")
	r.Env["PYTHONDONTWRITEBYTECODE"] = "1"
	if err := assertPipInputInstalled(r, target, previous, true); err != nil {
		return err
	}
	marker := filepath.Join(r.WorkDir, "project.txt")
	if err := os.WriteFile(marker, []byte("existing project must survive\n"), 0600); err != nil {
		return err
	}
	markerEvidence, err := digestFile(marker)
	if err != nil {
		return err
	}
	script, err := filepath.Abs("testdata/pip_inputs/configuration/snapshot_distributions.py")
	if err != nil {
		return err
	}
	before, err := r.Command("before-packages", r.Cell.Runtime, "-I", script, target, current.Project, leaf.Project)
	if err != nil {
		return err
	}
	report := filepath.Join(r.Root, "upgrade.json")
	if blocked {
		if err := writeFinding(r, "PyPI", current.Project, current.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	ev, err := pipSCFWCommand(r, "scfw", []string{"install", "--upgrade", "--no-cache-dir", "--only-binary=:all:", "--report", report, current.Project + "==" + current.Version, leaf.Project + "==" + leaf.Version})
	if err := checkPipInvocation(r, ev, err, blocked, false, []candidate{current}); err != nil {
		return err
	}
	expected := current
	if blocked {
		expected = previous
	}
	if err := assertPipInputInstalled(r, target, expected, true); err != nil {
		return err
	}
	if err := assertPipInputInstalled(r, target, leaf, true); err != nil {
		return err
	}
	after, err := r.Command("after-packages", r.Cell.Runtime, "-I", script, target, current.Project, leaf.Project)
	if err != nil {
		return err
	}
	if blocked && before.Stdout.SHA256 != after.Stdout.SHA256 {
		return fmt.Errorf("blocked upgrade modified existing package bytes")
	}
	if err := verifyGraphFile(markerEvidence); err != nil {
		return err
	}
	r.Result.Evidence["preserved-project"] = markerEvidence
	if !blocked {
		var actual pipGraphReport
		if err := readJSON(report, &actual); err != nil {
			return err
		}
		if err := matchPipInputReport(actual, []candidate{current}); err != nil {
			return err
		}
		if err := r.Keep("upgrade-report", report); err != nil {
			return err
		}
	}
	r.Result.Observations["old_version"] = previous.Version
	r.Result.Observations["new_version"] = current.Version
	return nil
}
func runPipVersionBoundary(r *caseRun, variant string) error {
	if err := preparePipInvocation(r); err != nil {
		return err
	}
	target := filepath.Join(r.Root, "installed")
	args := []string{"install", "--no-cache-dir", "--no-deps", "--only-binary=:all:", "--target", target, r.Candidate.Project + "==" + r.Candidate.Version}
	if variant == "informational" {
		args = []string{"--version"}
	}
	if variant == "proxy-block" {
		if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	ev, commandErr := pipSCFWCommand(r, "scfw", args)
	if ev.TimedOut || ev.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if strings.HasPrefix(variant, "proxy-") {
		blocked := variant == "proxy-block"
		if err := checkPipInvocation(r, ev, commandErr, blocked, false, []candidate{r.Candidate}); err != nil {
			return err
		}
		return assertPipInputInstalled(r, target, r.Candidate, !blocked)
	}
	text, err := os.ReadFile(ev.Stderr.Path)
	if err != nil {
		return err
	}
	if variant == "guarded-install" {
		if ev.ExitCode == 0 || !strings.Contains(string(text), "pip before v22.2.0 is not supported") {
			return fmt.Errorf("missing pip resolution minimum guard: exit%d: %v", ev.ExitCode, commandErr)
		}
		if records, err := readPolicy(r.Env["SCFW_LOG_FILE"]); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("guard rejection must precede policy: %+v, %v", records, err)
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "REJECT"
		if err := assertPipInputInstalled(r, target, r.Candidate, false); err != nil {
			return err
		}
		return assertCleanup(r, string(text))
	}
	if err := checkPipInvocation(r, ev, commandErr, false, true, nil); err != nil {
		return err
	}
	output, err := os.ReadFile(ev.Stdout.Path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(output), "pip "+r.Cell.ManagerVersion+" ") {
		return fmt.Errorf("informational command lost native version")
	}
	return nil
}
