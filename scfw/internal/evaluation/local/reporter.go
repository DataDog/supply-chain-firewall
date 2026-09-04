// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package local

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/home"
)

const (
	// The environment variable under which the local file reporter looks for a
	// log file to write to instead of the default file.
	logFileVar = "SCFW_LOG_FILE"

	// The default local log file within SCFW's home directory.
	logFileName = "scfw.log"
)

// FileReporter reports firewall outcomes by appending one JSON line per run to
// a local log file. Reporting to the file never changes the outcome of a run.
type FileReporter struct {
	path string
}

// NewFileReporter returns a FileReporter writing to the file named by
// SCFW_LOG_FILE or, failing that, the default log file in SCFW's home
// directory. Without either, the reporter is a no-op.
func NewFileReporter() *FileReporter {
	if path := os.Getenv(logFileVar); path != "" {
		return &FileReporter{path: path}
	}
	if dir := home.Dir(); dir != "" {
		return &FileReporter{path: filepath.Join(dir, logFileName)}
	}
	return &FileReporter{}
}

// ReportFirewallOutcome appends the outcome of a completed run to the reporter's
// log file as a single JSON line.
func (r *FileReporter) ReportFirewallOutcome(
	_ context.Context,
	installTimestamp time.Time,
	command []string,
	packageManagerName, executable, repository string,
	evaluationReport evaluation.ScfwPolicyEvaluationReport,
	resolvedOutcome evaluation.Outcome,
) error {
	if r.path == "" {
		return nil
	}

	record := runRecord{
		Timestamp:      installTimestamp.Format(time.RFC3339),
		Command:        strings.Join(command, " "),
		PackageManager: packageManagerName,
		Executable:     executable,
		Repository:     repository,
		Outcome:        string(resolvedOutcome),
		Packages:       evaluationReport.Results,
	}

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal run record: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("failed to create local log directory: %w", err)
	}
	file, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open local log file: %w", err)
	}
	defer file.Close() //nolint:errcheck

	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("failed to write local log record: %w", err)
	}
	return nil
}

// runRecord is the JSON shape of one reported run.
type runRecord struct {
	Timestamp      string                               `json:"timestamp"`
	Command        string                               `json:"command"`
	PackageManager string                               `json:"package_manager"`
	Executable     string                               `json:"executable"`
	Repository     string                               `json:"repository"`
	Outcome        string                               `json:"outcome"`
	Packages       []evaluation.PackageEvaluationResult `json:"packages"`
}
