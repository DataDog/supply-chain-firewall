//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHarnessSelection(t *testing.T) {
	c := cell{ID: "pilot", Manager: "pip", Modes: []string{"resolution", "proxy"}, Suites: []string{"pip-baseline"}}
	cases, err := selectCases(c, []string{"pip-baseline"})
	if err != nil || len(cases) == 0 {
		t.Fatalf("selection: %v, %d cases", err, len(cases))
	}
	for _, selection := range [][]string{nil, {"unknown"}, {"pip-baseline", "pip-baseline"}} {
		if _, err := selectCases(c, selection); err == nil {
			t.Fatalf("accepted invalid selection: %v", selection)
		}
	}
	if err := reconcile(cases, nil); err == nil {
		t.Fatal("accepted missing results")
	}
	results := make([]result, len(cases))
	for i, item := range cases {
		results[i] = result{ID: item.ID, Status: "PASS"}
	}
	if err := reconcile(cases, results); err != nil {
		t.Fatal(err)
	}
	results[0].Status = "PRECONDITION_UNAVAILABLE"
	if err := reconcile(cases, results); err == nil {
		t.Fatal("unavailable input passed")
	}
	results[0].Status = "PASS"
	results = append(results, results[0])
	if err := reconcile(cases, results); err == nil {
		t.Fatal("duplicate result passed")
	}
}

func TestHarnessIsolation(t *testing.T) {
	t.Setenv("DD_API_KEY", "must-not-leak")
	t.Setenv("PIP_INDEX_URL", "https://user:secret@example.invalid")
	before := os.Environ()
	env, err := isolatedEnvironment(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if env["DD_API_KEY"] != "" || strings.Contains(env["PIP_INDEX_URL"], "secret") {
		t.Fatal("inherited credentials")
	}
	if !reflect.DeepEqual(before, os.Environ()) {
		t.Fatal("mutated parent environment")
	}
	if env["SCFW_MODE"] != "local" || env["PIP_CONFIG_FILE"] != os.DevNull {
		t.Fatal("missing isolation")
	}
}

func TestHarnessBoundedProcess(t *testing.T) {
	root := t.TempDir()
	script, err := filepath.Abs("testdata/pip_baseline/timeout.sh")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ev, err := runCommand(ctx, root, map[string]string{"PATH": os.Getenv("PATH")}, root, "/bin/sh", script)
	if err == nil || !ev.TimedOut {
		t.Fatalf("timeout was not reported: %+v %v", ev, err)
	}
	if _, err := os.Stat(ev.Stderr.Path); err != nil {
		t.Fatal(err)
	}
}

func TestHarnessCandidateValidation(t *testing.T) {
	var fixtures map[string]candidate
	if err := readJSON("testdata/pip_baseline/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	if err := validateCandidate(fixtures["old"], now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing_hash", "future_fetch", "expired"} {
		if err := validateCandidate(fixtures[name], now); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestHarnessOutputPaths(t *testing.T) {
	for _, path := range []string{"", "relative"} {
		if err := requireAbsolute(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if err := requireAbsolute(filepath.Join(t.TempDir(), "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestHarnessRejectsFalseGreenInventory(t *testing.T) {
	c := cell{ID: "pilot", Manager: "pip", Modes: []string{"resolution", "proxy"}, Suites: []string{"pip-baseline"}}
	original := suites["pip-baseline"]
	defer func() { suites["pip-baseline"] = original }()
	for _, invalid := range []string{"unknown-id", "duplicate", "path-traversal", "no-applicable-case"} {
		t.Run(invalid, func(t *testing.T) {
			entries := append([]scenario(nil), original...)
			switch invalid {
			case "unknown-id":
				entries[0].Scenario = "UNKNOWN-99"
			case "duplicate":
				entries = append(entries, entries[0])
			case "path-traversal":
				entries[0].Variant = ".."
			case "no-applicable-case":
				for i := range entries {
					entries[i].Manager = "unsupported"
				}
			}
			suites["pip-baseline"] = entries
			if _, err := selectCases(c, []string{"pip-baseline"}); err == nil {
				t.Fatalf("accepted %s", invalid)
			}
		})
	}
}

func TestHarnessFilteredCasesCannotPass(t *testing.T) {
	root := t.TempDir()
	var m matrix
	if err := readJSON("testdata/matrix.json", &m); err != nil {
		t.Fatal(err)
	}
	matrixPath := filepath.Join(root, "matrix.json")
	if err := writeJSON(matrixPath, m); err != nil {
		t.Fatal(err)
	}
	discoveryPath := filepath.Join(root, "discovery.json")
	if err := writeJSON(discoveryPath, discovery{SchemaVersion: schemaVersion, ID: "offline-filter-probe", Candidates: map[string]candidate{}}); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PATH": os.Getenv("PATH"), "SCFW_E2E_BINARY": filepath.Join(root, "missing-scfw"), "SCFW_E2E_MATRIX": matrixPath, "SCFW_E2E_CELL": m.Cells[0].ID, "SCFW_E2E_SUITES": "pip-baseline", "SCFW_E2E_OUTPUT": filepath.Join(root, "output"), "SCFW_E2E_DISCOVERY": discoveryPath}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := runCommand(ctx, filepath.Join(root, "probe"), env, cwd, executable, "-test.run=^TestE2E$/^not-a-case$")
	if evidence.TimedOut {
		t.Fatal(err)
	}
	if err == nil {
		t.Fatal("filtered, unexecuted cases passed")
	}
	var aggregate struct {
		Results []result `json:"results"`
	}
	if err := readJSON(filepath.Join(root, "output", "results.json"), &aggregate); err != nil {
		t.Fatal(err)
	}
	if len(aggregate.Results) == 0 {
		t.Fatal("missing filtered-case evidence")
	}
	for _, result := range aggregate.Results {
		if result.Status != "INFRASTRUCTURE_FAILURE" || !strings.Contains(result.Reason, "not executed") {
			t.Fatalf("unexpected filtered-case result: %+v", result)
		}
	}
}

func TestHarnessEvidenceOutsideRepository(t *testing.T) {
	source, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "go.mod")); err != nil {
		t.Fatalf("expected the E2E package directly below the repository root: %v", err)
	}
	manifest, err := filepath.Abs("testdata/matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var m matrix
	if err := readJSON(manifest, &m); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCFW_E2E_MATRIX", manifest)
	t.Setenv("SCFW_E2E_DISCOVERY", filepath.Join(t.TempDir(), "discovery.json"))
	t.Setenv("SCFW_E2E_CELL", m.Cells[0].ID)
	t.Setenv("SCFW_E2E_SUITES", "pip-baseline")
	for _, output := range []string{source, filepath.Join(source, "evidence")} {
		t.Setenv("SCFW_E2E_OUTPUT", output)
		if _, err := loadInputs(); err == nil || !strings.Contains(err.Error(), "outside the source tree") {
			t.Fatalf("accepted output within the repository: %q, %v", output, err)
		}
	}
	// A sibling is outside this checkout even when both share a worktree parent.
	output := filepath.Join(filepath.Dir(source), filepath.Base(source)+"-evidence")
	t.Setenv("SCFW_E2E_OUTPUT", output)
	if _, err := loadInputs(); err != nil {
		t.Fatalf("rejected output beside the repository: %v", err)
	}
}
