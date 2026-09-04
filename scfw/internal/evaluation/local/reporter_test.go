// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package local

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
)

func TestFileReporterAppendsJSONLines(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "scfw.log")
	t.Setenv(logFileVar, logFile)

	r := NewFileReporter()
	report := evaluation.ScfwPolicyEvaluationReport{
		Outcome: evaluation.OutcomeBlock,
		Results: []evaluation.PackageEvaluationResult{{
			Ecosystem:      "npm",
			PackageName:    "evil",
			PackageVersion: "1.0.0",
			Outcome:        evaluation.OutcomeBlock,
		}},
	}

	err := r.ReportFirewallOutcome(context.Background(), time.Now(), []string{"npm", "install", "evil"},
		"npm", "/usr/bin/npm", "https://example.com/repo.git", report, evaluation.OutcomeBlock)
	if err != nil {
		t.Fatalf("ReportFirewallOutcome() returned unexpected error: %v", err)
	}
	err = r.ReportFirewallOutcome(context.Background(), time.Now(), []string{"npm", "install", "ok"},
		"npm", "/usr/bin/npm", "", evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, evaluation.OutcomeAllow)
	if err != nil {
		t.Fatalf("ReportFirewallOutcome() returned unexpected error: %v", err)
	}

	file, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("failed to open log file: %v", err)
	}
	defer file.Close()

	var records []runRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record runRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("failed to decode log line %q: %v", scanner.Text(), err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("log records = %d, want 2", len(records))
	}
	if records[0].Outcome != "BLOCK" || records[0].Command != "npm install evil" ||
		records[0].PackageManager != "npm" || records[0].Executable != "/usr/bin/npm" ||
		records[0].Repository != "https://example.com/repo.git" {
		t.Errorf("first record = %+v, want the blocked run", records[0])
	}
	if records[1].Outcome != "ALLOW" {
		t.Errorf("second record outcome = %q, want ALLOW", records[1].Outcome)
	}
	if !strings.HasPrefix(records[0].Timestamp, "20") {
		t.Errorf("record timestamp = %q, want an RFC3339 timestamp", records[0].Timestamp)
	}
	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatalf("failed to stat log file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file permissions = %o, want 600", perm)
	}
}

func TestFileReporterDefaultsToScfwHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SCFW_HOME", home)
	t.Setenv(logFileVar, "")

	r := NewFileReporter()
	err := r.ReportFirewallOutcome(context.Background(), time.Now(), []string{"npm", "install"},
		"npm", "npm", "", evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, evaluation.OutcomeAllow)
	if err != nil {
		t.Fatalf("ReportFirewallOutcome() returned unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, logFileName)); err != nil {
		t.Errorf("default log file not written: %v", err)
	}
}
