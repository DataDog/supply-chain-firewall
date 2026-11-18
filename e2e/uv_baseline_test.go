//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHarnessUVToolEligibility(t *testing.T) {
	var fixtures map[string]uvReleaseMetadata
	if err := readJSON("testdata/uv/baseline/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	for name, metadata := range fixtures {
		_, eligible := uvToolArtifact(metadata, "3.12.10", now)
		if eligible != (name == "old") {
			t.Fatalf("%s eligibility = %v", name, eligible)
		}
	}
}

func TestHarnessUVVersionOrdering(t *testing.T) {
	if uvVersionCompare("10.0", "6.1") <= 0 || uvVersionCompare("6.1", "6.0") <= 0 || uvVersionCompare("6.1", "6.1") != 0 {
		t.Fatal("tool upgrades need numeric version ordering")
	}
}

type uvReleaseMetadata struct {
	Info struct {
		Name         string   `json:"name"`
		Version      string   `json:"version"`
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
	URLs []pypiFile `json:"urls"`
}

func uvVersionCompare(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(left), len(right)) {
		x, y := 0, 0
		if i < len(left) {
			x, _ = strconv.Atoi(left[i])
		}
		if i < len(right) {
			y, _ = strconv.Atoi(right[i])
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

func uvToolArtifact(metadata uvReleaseMetadata, python string, now time.Time) (pypiFile, bool) {
	if len(metadata.Info.RequiresDist) != 0 {
		return pypiFile{}, false
	}
	for _, file := range metadata.URLs {
		if !file.Yanked && !file.UploadTime.IsZero() && file.UploadTime.Before(now.Add(-48*time.Hour)) &&
			strings.HasSuffix(file.Filename, "-py3-none-any.whl") && len(file.Digests.SHA256) == 64 &&
			compatiblePythonFloor(file.RequiresPython, python) {
			return file, true
		}
	}
	return pypiFile{}, false
}

func discoverUVTool(ctx context.Context, cell cell, output string) (candidate, error) {
	var names []string
	if err := readJSON("testdata/uv/baseline/tool_candidates.json", &names); err != nil {
		return candidate{}, err
	}
	now := time.Now().UTC()
	var rejected []string
	for _, name := range names {
		var project pypiMetadata
		projectEvidence, err := fetchJSON(ctx, "https://pypi.org/pypi/"+name+"/json", filepath.Join(output, name+".json"), &project)
		if err != nil {
			return candidate{}, err
		}
		var versions []string
		for version := range project.Releases {
			if regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(version) {
				versions = append(versions, version)
			}
		}
		slices.SortFunc(versions, func(a, b string) int { return uvVersionCompare(b, a) })
		var choices []candidate
		for _, version := range versions[:min(len(versions), 10)] {
			if len(choices) > 0 && uvVersionCompare(choices[0].Version, version) <= 0 {
				continue
			}
			var release uvReleaseMetadata
			metadata, err := fetchJSON(ctx, "https://pypi.org/pypi/"+name+"/"+version+"/json", filepath.Join(output, name+"-"+version+".json"), &release)
			if err != nil {
				return candidate{}, err
			}
			file, eligible := uvToolArtifact(release, cell.RuntimeVersion, now)
			if !eligible {
				rejected = append(rejected, name+"=="+version+": no eligible old dependency-free wheel")
				continue
			}
			choices = append(choices, candidate{
				Ecosystem: "pypi", Project: name, Version: version, Property: "old-cli-tool", Module: name,
				Metadata:   []metadataEvidence{projectEvidence, metadata},
				Artifacts:  []artifact{{Name: file.Filename, URL: file.URL, SHA256: file.Digests.SHA256, UploadedAt: file.UploadTime, RequiresPython: file.RequiresPython}},
				ObservedAt: now, LatestValidStart: now.Add(24 * time.Hour),
				Constraints: []string{"dependency-free universal wheel", cell.RuntimeVersion},
				Evidence:    append(slices.Clone(rejected), "numeric release order; exact pins retained before execution"),
			})
			if len(choices) == 2 {
				choices[0].Related = map[string]candidate{"bootstrap": choices[1]}
				return choices[0], nil
			}
		}
	}
	return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no public tool upgrade pair: %v", rejected))
}

func validateUVToolPins(c candidate, now time.Time) error {
	old, ok := c.Related["bootstrap"]
	if !ok || old.Project != c.Project || old.Ecosystem != c.Ecosystem || uvVersionCompare(c.Version, old.Version) <= 0 {
		return fmt.Errorf("invalid tool upgrade pins")
	}
	if err := validateCandidate(c, now); err != nil {
		return err
	}
	return validateCandidate(old, now)
}

func revalidateUVTool(ctx context.Context, c candidate, output string) error {
	if err := validateUVToolPins(c, time.Now().UTC()); err != nil {
		return classified("PRECONDITION_UNAVAILABLE", err)
	}
	for label, choice := range map[string]candidate{"target": c, "bootstrap": c.Related["bootstrap"]} {
		if err := revalidatePyPI(ctx, choice, filepath.Join(output, label)); err != nil {
			return err
		}
	}
	return nil
}

func TestHarnessUVRelatedPins(t *testing.T) {
	var fixtures map[string]candidate
	if err := readJSON("testdata/pip_baseline/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	current := fixtures["old"]
	current.Version = "6.1"
	previous := fixtures["old"]
	previous.Version = "6.0"
	current.Related = map[string]candidate{"bootstrap": previous}
	if err := validateUVToolPins(current, now); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "expired", "identity", "hash"} {
		changed := current
		old := previous
		switch kind {
		case "expired":
			old.LatestValidStart = now.Add(-time.Second)
		case "identity":
			old.Project = "different"
		case "hash":
			old.Artifacts = slices.Clone(old.Artifacts)
			old.Artifacts[0].SHA256 = ""
			old.Artifacts[0].Integrity = ""
		}
		changed.Related = map[string]candidate{"bootstrap": old}
		if kind == "missing" {
			changed.Related = nil
		}
		if err := validateUVToolPins(changed, now); err == nil {
			t.Fatalf("accepted %s related input", kind)
		}
	}
}

type uvOptions struct {
	operation, flag, direct                  string
	block, errorOnBlock, spaces, nativeError bool
}

func init() {
	discoverers["pypi-uv-tool"] = discoverUVTool
	revalidators["pypi-uv-tool"] = revalidateUVTool
	add := func(id, variant, key string, options uvOptions) {
		profile := "public-pypi"
		if key == "" {
			profile = "none"
		}
		suites["uv-baseline"] = append(suites["uv-baseline"], scenario{
			Scenario: id, Variant: variant, Manager: "uv", Mode: "proxy", Backend: "local", RegistryProfile: profile,
			DiscoveryKey: key, Timeout: 3 * time.Minute, Run: func(r *caseRun) error { return runUVBaseline(r, options) },
		})
	}
	pip := uvOptions{operation: "pip", flag: "1"}
	add("CORE-01", "uv-pip-allow", "pypi-old", pip)
	add("UV-01", "uv-pip-install", "pypi-old", pip)
	for _, flag := range []string{"", "0", "true", "1"} {
		name := flag
		if name == "" {
			name = "unset"
		}
		add("CORE-10", "uv-proxy-flag-"+name, "pypi-old", uvOptions{operation: "pip", flag: flag})
	}
	for _, errorFlag := range []bool{false, true} {
		name := "default"
		if errorFlag {
			name = "error-on-block"
		}
		add("CORE-02", "uv-block-"+name, "pypi-old", uvOptions{operation: "pip", flag: "1", block: true, errorOnBlock: errorFlag})
	}
	add("CORE-12", "uv-executable-spaces", "pypi-old", uvOptions{operation: "pip", flag: "1", spaces: true})
	add("CORE-12", "uvx-executable-spaces", "pypi-uv-tool", uvOptions{operation: "uvx", flag: "1", spaces: true})
	for _, operation := range []string{"install", "run", "upgrade", "uvx"} {
		for _, blocked := range []bool{false, true} {
			action := "allow"
			if blocked {
				action = "block"
			}
			add("UV-03", "uv-"+operation+"-"+action, "pypi-uv-tool", uvOptions{operation: operation, flag: "1", block: blocked})
		}
	}
	add("UV-03", "uv-tool-child-exit", "pypi-uv-tool", uvOptions{operation: "run", flag: "1", nativeError: true})
	for _, direct := range []string{"command", "script", "module", "stdin", "with", "help", "version"} {
		key := ""
		if direct == "with" {
			key = "pypi-uv-tool"
		}
		add("UV-05", "uv-run-"+direct, key, uvOptions{direct: direct, flag: "1"})
	}
	for _, id := range []string{"REPORT-01", "LIFE-01"} {
		for _, blocked := range []bool{false, true} {
			action := "allow"
			if blocked {
				action = "block"
			}
			add(id, "uv-"+action, "pypi-old", uvOptions{operation: "pip", flag: "1", block: blocked})
		}
	}
}

func prepareUV(r *caseRun, options uvOptions) (string, string, error) {
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	r.Env["UV_PYTHON"], r.Env["UV_PYTHON_DOWNLOADS"] = r.Cell.Runtime, "never"
	r.Env["UV_DEFAULT_INDEX"] = "https://pypi.org/simple"
	for key, dir := range map[string]string{"UV_CACHE_DIR": "uv-cache", "UV_TOOL_DIR": "tools", "UV_TOOL_BIN_DIR": "tools-bin"} {
		r.Env[key] = filepath.Join(r.Root, dir)
		if err := os.MkdirAll(r.Env[key], 0700); err != nil {
			return "", "", err
		}
	}
	delete(r.Env, "SCFW_PROXY_ENABLED")
	if options.flag != "" {
		r.Env["SCFW_PROXY_ENABLED"] = options.flag
	}
	launcher, executable := "uv", r.Cell.Executable
	if options.operation == "uvx" {
		launcher, executable = "uvx", filepath.Join(filepath.Dir(executable), "uvx")
		command, err := r.Command("uvx-version", executable, "--version")
		if err != nil {
			return "", "", classified("INFRASTRUCTURE_FAILURE", err)
		}
		data, err := os.ReadFile(command.Stdout.Path)
		if err != nil {
			return "", "", err
		}
		if !strings.HasPrefix(string(data), "uvx "+r.Cell.ManagerVersion+" ") && strings.TrimSpace(string(data)) != "uvx "+r.Cell.ManagerVersion {
			return "", "", classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("uvx does not match pinned uv version: %s", data))
		}
	}
	if options.spaces {
		directory := filepath.Join(r.Root, "manager path with spaces")
		if err := os.MkdirAll(directory, 0700); err != nil {
			return "", "", err
		}
		link := filepath.Join(directory, launcher)
		if err := os.Symlink(executable, link); err != nil {
			return "", "", err
		}
		executable = link
	}
	return launcher, executable, nil
}

func uvFirewallArgs(r *caseRun, launcher, executable string, options uvOptions, args []string) []string {
	argv := []string{r.Binary, "run", "--executable", executable}
	if options.errorOnBlock {
		argv = append(argv, "--error-on-block")
	}
	return append(append(argv, "--", launcher), args...)
}

func runUVBaseline(r *caseRun, options uvOptions) error {
	launcher, executable, err := prepareUV(r, options)
	if err != nil {
		return err
	}
	if options.direct != "" {
		return runUVDirect(r, executable, options)
	}
	c := r.Candidate
	if options.block {
		if err := writeFinding(r, "PyPI", c.Project, c.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	python := ""
	var args []string
	switch options.operation {
	case "pip":
		venv := filepath.Join(r.Root, "venv")
		if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
			return classified("INFRASTRUCTURE_FAILURE", err)
		}
		python = filepath.Join(venv, "bin", "python")
		args = []string{"pip", "install", "--python", python, c.Project + "==" + c.Version}
	case "install":
		args = []string{"tool", "install", c.Project + "==" + c.Version}
	case "upgrade":
		old := c.Related["bootstrap"]
		requirement := c.Project + ">=" + old.Version + ",<=" + c.Version
		if _, err := r.Command("bootstrap", r.Cell.Executable, "tool", "install", requirement, "--resolution", "lowest-direct"); err != nil {
			return classified("INFRASTRUCTURE_FAILURE", err)
		}
		installed := filepath.Join(r.Env["UV_TOOL_DIR"], c.Project, "bin", "python")
		if err := assertUVInstalled(r, installed, old.Version, "bootstrap"); err != nil {
			return err
		}
		args = []string{"tool", "upgrade", c.Project + "==" + c.Version}
	case "run", "uvx":
		if options.operation == "run" {
			args = []string{"tool", "run"}
		}
		args = append(args, "--from", c.Project+"=="+c.Version, c.Project)
		if options.nativeError {
			args = append(args, "-t", "unused", "--scfw-intentionally-invalid")
		} else if options.spaces {
			args = append(args, "-t", "SCFW E2E argument with spaces")
		} else {
			args = append(args, "--help")
		}
	default:
		return fmt.Errorf("unknown uv operation %q", options.operation)
	}
	command, commandErr := r.Command("scfw", uvFirewallArgs(r, launcher, executable, options, args)...)
	if command.TimedOut {
		return commandErr
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	stdout, err := os.ReadFile(command.Stdout.Path)
	if err != nil {
		return err
	}
	r.Result.Observations["proxy_flag"] = options.flag
	if options.flag != "1" {
		if command.ExitCode == 0 || !strings.Contains(string(stderr), "require proxy mode") {
			return fmt.Errorf("uv package operation did not reject missing proxy mode")
		}
		if err := assertUVNoPolicy(r); err != nil {
			return err
		}
		if err := assertUVInstalled(r, python, "", "rejected"); err != nil {
			return err
		}
		r.Result.ResolvedAction = "REJECTED"
		return assertUVNoProxy(r, string(stderr))
	}
	expectedExit := 0
	if options.block || options.nativeError {
		expectedExit = 2
	}
	if options.operation == "upgrade" && options.block {
		expectedExit = 1
	}
	if command.ExitCode != expectedExit {
		return fmt.Errorf("uv exit=%d, want%d: %v", command.ExitCode, expectedExit, commandErr)
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	outcome := "ALLOW"
	if options.block {
		outcome = "BLOCK"
	}
	if err := assertPolicy(records, c, launcher, executable, outcome); err != nil {
		return err
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
	if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	expectedVersion := c.Version
	if options.block {
		expectedVersion = ""
	}
	switch options.operation {
	case "pip":
		if err := assertUVInstalled(r, python, expectedVersion, "installed"); err != nil {
			return err
		}
	case "install", "upgrade":
		if options.operation == "upgrade" && options.block {
			expectedVersion = c.Related["bootstrap"].Version
		}
		python = filepath.Join(r.Env["UV_TOOL_DIR"], c.Project, "bin", "python")
		if err := assertUVInstalled(r, python, expectedVersion, "installed"); err != nil {
			return err
		}
		tool := filepath.Join(r.Env["UV_TOOL_BIN_DIR"], c.Project)
		if expectedVersion == "" {
			if _, err := os.Lstat(tool); !os.IsNotExist(err) {
				return fmt.Errorf("blocked tool left an executable")
			}
		} else {
			help, err := r.Command("installed-tool", tool, "--help")
			if err != nil {
				return err
			}
			data, err := os.ReadFile(help.Stdout.Path)
			if err != nil {
				return err
			}
			if !strings.Contains(strings.ToLower(string(data)), c.Project) {
				return fmt.Errorf("installed tool did not execute")
			}
		}
	case "run", "uvx":
		if options.block {
			if len(stdout) != 0 {
				return fmt.Errorf("blocked tool produced child output")
			}
		} else if options.nativeError {
			if !strings.Contains(string(stderr), "unrecognized arguments") {
				return fmt.Errorf("native tool error was not observed")
			}
		} else {
			expected, output := c.Project, strings.ToLower(string(stdout))
			if options.spaces {
				expected, output = "SCFW E2E argument with spaces", string(stdout)
			}
			if !strings.Contains(output, expected) {
				return fmt.Errorf("allowed tool did not produce expected output")
			}
		}
	}
	return assertCleanup(r, string(stderr))
}

func assertUVInstalled(r *caseRun, python, expected, label string) error {
	observation := struct {
		Present bool   `json:"present"`
		Version string `json:"version"`
	}{}
	if _, err := os.Stat(python); err == nil {
		script, err := filepath.Abs("testdata/uv/baseline/installed.py")
		if err != nil {
			return err
		}
		command, err := r.Command(label+"-state", python, "-I", script, r.Candidate.Project)
		if err != nil {
			return err
		}
		if err := readJSON(command.Stdout.Path, &observation); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	r.Result.Observations[label] = observation
	if observation.Present != (expected != "") || observation.Version != expected {
		return fmt.Errorf("%s install state: %+v, expected %q", label, observation, expected)
	}
	return nil
}

func assertUVNoPolicy(r *caseRun) error {
	data, err := os.ReadFile(r.Env["SCFW_LOG_FILE"])
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(strings.TrimSpace(string(data))) != 0 {
		return fmt.Errorf("uninspected uv command produced policy records")
	}
	return nil
}

func assertUVNoProxy(r *caseRun, stderr string) error {
	if strings.Contains(stderr, "started package manager proxy") {
		return fmt.Errorf("uninspected uv command started an invocation proxy")
	}
	direct := *r
	direct.Spec.Mode = "direct"
	return assertCleanup(&direct, stderr)
}

func runUVDirect(r *caseRun, executable string, options uvOptions) error {
	keys := []string{"HTTPS_PROXY", "SSL_CERT_FILE", "GIT_SSL_CAINFO", "UV_CONFIG_FILE", "SCFW_E2E_SENTINEL"}
	r.Env["SCFW_E2E_SENTINEL"] = "retained-value"
	r.Env["GIT_SSL_CAINFO"] = filepath.Join(r.Root, "unused-git-ca.pem")
	r.Env["UV_CONFIG_FILE"] = filepath.Join(r.Root, "direct-config.toml")
	if err := os.WriteFile(r.Env["UV_CONFIG_FILE"], []byte("# direct-run configuration\n"), 0600); err != nil {
		return err
	}
	if options.direct != "with" {
		r.Env["HTTPS_PROXY"] = "http://127.0.0.1:1"
		r.Env["SSL_CERT_FILE"] = filepath.Join(r.Root, "missing-ca.pem")
	}
	probe, err := os.ReadFile("testdata/uv/baseline/probe.py")
	if err != nil {
		return err
	}
	path := filepath.Join(r.WorkDir, "e2e_probe.py")
	if err := os.WriteFile(path, probe, 0600); err != nil {
		return err
	}
	args := []string{"run", "--no-project", "--python", r.Cell.Runtime}
	childArgs := []string{"argument with spaces", "--unchanged"}
	input := "input stays untouched\n"
	switch options.direct {
	case "command":
		args = append(args, "python", path)
	case "script":
		args = append(args, "--script", path)
	case "module":
		args = append(args, "-m", "e2e_probe")
	case "stdin":
		args = append(args, "-")
		input = string(probe)
	case "with":
		if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
		r.Env["SCFW_E2E_EXPECT_PACKAGE"] = r.Candidate.Project
		r.Env["SCFW_E2E_EXPECT_VERSION"] = r.Candidate.Version
		args = append(args, "--with", r.Candidate.Project+"=="+r.Candidate.Version, "python", path)
	case "help":
		args = []string{"run", "--help"}
	case "version":
		args = []string{"--version"}
	}
	expectedExit := 7
	if options.direct == "help" || options.direct == "version" {
		expectedExit = 0
		input = ""
	} else {
		args = append(args, childArgs...)
	}
	command, commandErr := r.CommandInput("scfw", input, uvFirewallArgs(r, "uv", executable, options, args)...)
	if command.TimedOut {
		return commandErr
	}
	if command.ExitCode != expectedExit {
		return fmt.Errorf("direct uv exit=%d, want%d: %v", command.ExitCode, expectedExit, commandErr)
	}
	if expectedExit == 7 {
		var state struct {
			Args           []string           `json:"args"`
			Stdin          string             `json:"stdin"`
			Env            map[string]*string `json:"env"`
			PackageVersion string             `json:"package_version"`
		}
		if err := readJSON(command.Stdout.Path, &state); err != nil {
			return err
		}
		expectedInput := input
		if options.direct == "stdin" {
			expectedInput = ""
		}
		if !slices.Equal(state.Args, childArgs) || state.Stdin != expectedInput {
			return fmt.Errorf("direct uv changed argv or stdin")
		}
		for _, key := range keys {
			value, present := r.Env[key]
			actual := state.Env[key]
			if present != (actual != nil) || (actual != nil && *actual != value) {
				return fmt.Errorf("direct uv changed %s", key)
			}
		}
		if options.direct == "with" && state.PackageVersion != r.Candidate.Version {
			return fmt.Errorf("direct --with did not install exact dependency")
		}
		r.Result.Observations["child"] = state
	} else {
		data, err := os.ReadFile(command.Stdout.Path)
		if err != nil {
			return err
		}
		expected := "Usage: uv run"
		if options.direct == "version" {
			expected = "uv " + r.Cell.ManagerVersion
		}
		if !strings.Contains(string(data), expected) {
			return fmt.Errorf("direct informational command did not execute")
		}
	}
	if err := assertUVNoPolicy(r); err != nil {
		return err
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	r.Result.ResolvedAction = "BYPASS"
	return assertUVNoProxy(r, string(stderr))
}
