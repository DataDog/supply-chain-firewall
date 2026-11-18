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
	"testing"
	"time"
)

type npmAgeOptions struct {
	name, minimum, flag            string
	warning, invalid, errorOnBlock bool
}

func init() {
	variants := []npmAgeOptions{
		{name: "recent-default", warning: true},
		{name: "recent-allow-warning", warning: true, flag: "--allow-on-warning", errorOnBlock: true},
		{name: "recent-block-warning", warning: true, flag: "--block-on-warning", errorOnBlock: true},
		{name: "old-default"},
		{name: "recent-disabled", minimum: "0"},
		{name: "recent-explicit24h", minimum: "24", warning: true, errorOnBlock: true},
		{name: "recent-explicit1h", minimum: "1"},
		{name: "recent-invalid-negative", minimum: "-1", warning: true, invalid: true, errorOnBlock: true},
		{name: "recent-invalid-noninteger", minimum: "invalid", warning: true, invalid: true, errorOnBlock: true},
	}
	for _, mode := range []string{"resolution", "proxy"} {
		for _, options := range variants {
			key := "npm-recent"
			if options.name == "old-default" {
				key = "npm-old"
			}
			suites["npm-recent"] = append(suites["npm-recent"], scenario{Scenario: "LOCAL-03", Variant: mode + "-" + options.name, Manager: "npm", Mode: mode, Backend: "local", RegistryProfile: "public-npm", DiscoveryKey: key, Timeout: 3 * time.Minute, Run: func(r *caseRun) error { return runNPMAge(r, options) }})
		}
	}
}

func runNPMAge(r *caseRun, options npmAgeOptions) error {
	c := r.Candidate
	if r.Spec.DiscoveryKey == "npm-recent" {
		if err := validateNPMRecentCell(c, r.Cell, time.Now().UTC()); err != nil {
			return err
		}
	} else if c.Artifacts[0].UploadedAt.After(time.Now().UTC().Add(-48 * time.Hour)) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("old control is not older than48h"))
	}
	var metadata npmMetadata
	if err := readJSON(filepath.Join(r.Root, "revalidation", "npm.json"), &metadata); err != nil {
		return err
	}
	if !compatibleNodeFloor(metadata.Versions[c.Version].Engines.Node, r.Cell.RuntimeVersion) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("revalidated release is incompatible with Node%s", r.Cell.RuntimeVersion))
	}
	before, err := prepareNPMProject(r)
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
	r.Result.Observations["publication"] = c.Artifacts[0]
	// No list is created, including in the cases whose WARN resolves to BLOCK.
	if _, err := os.Stat(filepath.Join(r.Env["SCFW_HOME"], "list_verifier")); !os.IsNotExist(err) {
		return fmt.Errorf("age test requires an absent findings-list directory: %v", err)
	}
	argv := []string{r.Binary, "run"}
	if options.flag != "" {
		argv = append(argv, options.flag)
	}
	if options.errorOnBlock {
		argv = append(argv, "--error-on-block")
	}
	args := []string{"npm", "install", c.Project + "@" + c.Version, "--ignore-scripts", "--no-audit", "--no-fund"}
	argv = append(append(argv, "--"), args...)
	// The runner revalidates before bootstrap; repeat freshness immediately before
	// SCFW and bound it across the actual process interval as well.
	if r.Spec.DiscoveryKey == "npm-recent" {
		if err := validateNPMRecentCell(c, r.Cell, time.Now().UTC()); err != nil {
			return err
		}
		if err := checkNPMRecentInterval(c, time.Now().UTC(), time.Now().UTC().Add(r.Spec.Timeout)); err != nil {
			return err
		}
	}
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	if r.Spec.DiscoveryKey == "npm-recent" {
		if err := checkNPMRecentInterval(c, command.StartedAt, command.EndedAt); err != nil {
			return err
		}
	}
	blocked := options.warning && r.Spec.Mode == "resolution" && options.flag != "--allow-on-warning"
	expectedExit := 0
	if blocked && options.errorOnBlock {
		expectedExit = 1
	}
	if command.ExitCode != expectedExit || command.Signal != "" {
		return fmt.Errorf("SCFW exit%d signal%q; want%d: %v", command.ExitCode, command.Signal, expectedExit, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") || strings.Contains(string(stderr), "falling back to dry-run resolution") {
		return fmt.Errorf("incorrect npm inspection mode")
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
		return fmt.Errorf("resolution produced%d records; want1", len(records))
	}
	if err := assertNPMAgePolicy(records, c, r.Cell.Executable, policy, action); err != nil {
		return err
	}
	for _, record := range records {
		if record.Repository != "https://example.invalid/scfw-e2e.git" || record.Command != strings.Join(args, " ") {
			return fmt.Errorf("incorrect age report repository or command")
		}
	}
	for name, original := range before {
		after, err := os.ReadFile(filepath.Join(r.WorkDir, name))
		if err != nil {
			return err
		}
		if blocked && !bytes.Equal(original, after) {
			return fmt.Errorf("warning BLOCK changed%s", name)
		}
		if err := r.Keep("after-"+name, filepath.Join(r.WorkDir, name)); err != nil {
			return err
		}
	}
	if err := assertNPMInstall(r, blocked); err != nil {
		return err
	}
	return assertCleanup(r, string(stderr))
}

func assertNPMAgePolicy(records []policyRecord, c candidate, executable, outcome, action string) error {
	if len(records) == 0 {
		return fmt.Errorf("missing age policy report")
	}
	for _, record := range records {
		if record.Manager != "npm" || record.Executable != executable || record.Timestamp.IsZero() || record.Outcome != action || len(record.Packages) != 1 {
			return fmt.Errorf("unexpected age report action or identity: %+v", record)
		}
		pkg := record.Packages[0]
		if !strings.EqualFold(pkg.Ecosystem, "npm") || pkg.Name != c.Project || pkg.Version != c.Version || pkg.Outcome != outcome {
			return fmt.Errorf("unexpected age package policy: %+v", pkg)
		}
		if len(pkg.Failures) != 0 {
			return fmt.Errorf("live verifier failure remains visible: %s", pkg.Failures)
		}
		wantFindings := 0
		if outcome == "WARN" {
			wantFindings = 1
		}
		if len(pkg.Findings) != wantFindings {
			return fmt.Errorf("expected%d isolated age findings, got%v", wantFindings, pkg.Findings)
		}
		for _, finding := range pkg.Findings {
			if finding.Verifier != "PackageAgeVerifier" || finding.Severity != "WARNING" || !strings.Contains(finding.Text, c.Project+"@"+c.Version) || !strings.Contains(finding.Text, "less than 24 hours ago") {
				return fmt.Errorf("warning does not prove default24h publication policy: %+v", finding)
			}
		}
	}
	return nil
}

func TestHarnessNPMAgePolicy(t *testing.T) {
	var fixtures map[string][]policyRecord
	if err := readJSON("testdata/age_npm/policy.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	c := candidate{Project: "fixture-leaf", Version: "1.0.0"}
	for _, action := range []string{"ALLOW", "BLOCK"} {
		records := fixtures["warning"]
		records[0].Outcome = action
		if err := assertNPMAgePolicy(records, c, "/npm", "WARN", action); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"list", "wrong-version", "other-finding", "wrong-threshold", "failure"} {
		if err := assertNPMAgePolicy(fixtures[name], c, "/npm", "WARN", "ALLOW"); err == nil {
			t.Errorf("accepted%s as isolated age warning", name)
		}
	}
	if err := assertNPMAgePolicy(fixtures["allowed"], c, "/npm", "ALLOW", "ALLOW"); err != nil {
		t.Fatal(err)
	}
}
