//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const schemaVersion = 1

type cell struct {
	ID             string   `json:"id"`
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
	Runner         string   `json:"runner"`
	Manager        string   `json:"manager"`
	Executable     string   `json:"executable"`
	ManagerVersion string   `json:"manager_version"`
	Runtime        string   `json:"runtime"`
	RuntimeVersion string   `json:"runtime_version"`
	Git            string   `json:"git"`
	GitVersion     string   `json:"git_version"`
	Provisioning   string   `json:"provisioning"`
	Modes          []string `json:"modes"`
	Capabilities   []string `json:"capabilities"`
	Suites         []string `json:"suites"`
}

type matrix struct {
	SchemaVersion int    `json:"schema_version"`
	Cells         []cell `json:"cells"`
}
type fileEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type metadataEvidence struct {
	URL       string       `json:"url"`
	FetchedAt time.Time    `json:"fetched_at"`
	Body      fileEvidence `json:"body"`
}
type artifact struct {
	Name           string    `json:"name"`
	URL            string    `json:"url"`
	SHA256         string    `json:"sha256,omitempty"`
	Integrity      string    `json:"integrity,omitempty"`
	UploadedAt     time.Time `json:"uploaded_at"`
	RequiresPython string    `json:"requires_python,omitempty"`
}
type candidate struct {
	Ecosystem        string             `json:"ecosystem"`
	Project          string             `json:"project"`
	Version          string             `json:"version"`
	Property         string             `json:"property"`
	Module           string             `json:"module,omitempty"`
	Metadata         []metadataEvidence `json:"metadata"`
	Artifacts        []artifact         `json:"artifacts"`
	ObservedAt       time.Time          `json:"observed_at"`
	LatestValidStart time.Time          `json:"latest_valid_start"`
	Constraints      []string           `json:"constraints"`
	Evidence         []string           `json:"evidence"`

	AgeThresholdHours int      `json:"age_threshold_hours,omitempty"`
	ApplicableCells   []string `json:"applicable_cells,omitempty"`
}
type discovery struct {
	SchemaVersion int                  `json:"schema_version"`
	ID            string               `json:"id"`
	Candidates    map[string]candidate `json:"candidates"`
}
type scenario struct {
	Scenario        string               `json:"scenario"`
	Variant         string               `json:"variant"`
	Manager         string               `json:"manager"`
	Mode            string               `json:"mode"`
	Backend         string               `json:"backend"`
	RegistryProfile string               `json:"registry_profile"`
	DiscoveryKey    string               `json:"discovery_key"`
	Capabilities    []string             `json:"capabilities"`
	Timeout         time.Duration        `json:"timeout_ns"`
	Run             func(*caseRun) error `json:"-"`
}
type plannedCase struct {
	scenario
	ID            string `json:"id"`
	Suite         string `json:"suite"`
	NotApplicable string `json:"not_applicable,omitempty"`
}
type commandEvidence struct {
	Argv        []string          `json:"argv"`
	Environment map[string]string `json:"environment"`
	Cwd         string            `json:"cwd"`
	StartedAt   time.Time         `json:"started_at"`
	EndedAt     time.Time         `json:"ended_at"`
	ExitCode    int               `json:"exit_code"`
	Signal      string            `json:"signal,omitempty"`
	TimedOut    bool              `json:"timed_out"`
	Stdout      fileEvidence      `json:"stdout"`
	Stderr      fileEvidence      `json:"stderr"`
}
type result struct {
	SchemaVersion  int                     `json:"schema_version"`
	ID             string                  `json:"id"`
	Cell           cell                    `json:"cell"`
	Spec           scenario                `json:"case"`
	Artifact       fileEvidence            `json:"artifact"`
	DiscoveryID    string                  `json:"discovery_id"`
	StartedAt      time.Time               `json:"started_at"`
	EndedAt        time.Time               `json:"ended_at"`
	Status         string                  `json:"status"`
	Reason         string                  `json:"reason,omitempty"`
	PolicyOutcome  string                  `json:"policy_outcome,omitempty"`
	ResolvedAction string                  `json:"resolved_action,omitempty"`
	SCFWExit       int                     `json:"scfw_exit"`
	SCFWSignal     string                  `json:"scfw_signal,omitempty"`
	Commands       []commandEvidence       `json:"commands"`
	Evidence       map[string]fileEvidence `json:"evidence"`
	Observations   map[string]any          `json:"observations"`
}

var suites = map[string][]scenario{}
var discoverers = map[string]func(context.Context, cell, string) (candidate, error){}
var revalidators = map[string]func(context.Context, candidate, string) error{}

type caseFailure struct {
	status string
	err    error
}

func (e caseFailure) Error() string { return e.err.Error() }
func classified(status string, err error) error {
	if err == nil {
		return nil
	}
	return caseFailure{status, err}
}

func validIDComponent(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, "/\\")
}
func requireAbsolute(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("required absolute path, got %q", path)
	}
	return nil
}
func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}
func selectCases(c cell, selected []string) ([]plannedCase, error) {
	if len(selected) == 0 {
		return nil, fmt.Errorf("empty suite selection")
	}
	var known []string
	if err := readJSON("testdata/scenario_ids.json", &known); err != nil {
		return nil, err
	}
	seen, seenSuites := map[string]bool{}, map[string]bool{}
	var cases []plannedCase
	for _, suite := range selected {
		entries, exists := suites[suite]
		if !exists || seenSuites[suite] || !slices.Contains(c.Suites, suite) {
			return nil, fmt.Errorf("unknown, duplicate or disabled suite %q", suite)
		}
		seenSuites[suite] = true
		for _, spec := range entries {
			if !slices.Contains(known, spec.Scenario) || !validIDComponent(spec.Variant) || spec.Run == nil || spec.Timeout <= 0 {
				return nil, fmt.Errorf("invalid scenario registration: %s/%s", spec.Scenario, spec.Variant)
			}
			item := plannedCase{scenario: spec, Suite: suite, ID: strings.Join([]string{c.ID, suite, spec.Scenario, spec.Variant}, "/")}
			if seen[item.ID] {
				return nil, fmt.Errorf("duplicate case %s", item.ID)
			}
			seen[item.ID] = true
			if spec.Manager != c.Manager {
				item.NotApplicable = "case requires manager " + spec.Manager
			}
			if !slices.Contains(c.Modes, spec.Mode) {
				item.NotApplicable = "case requires mode " + spec.Mode
			}
			for _, capability := range spec.Capabilities {
				if !slices.Contains(c.Capabilities, capability) {
					item.NotApplicable = "case requires declared capability " + capability
				}
			}
			cases = append(cases, item)
		}
	}
	if !slices.ContainsFunc(cases, func(c plannedCase) bool { return c.NotApplicable == "" }) {
		return nil, fmt.Errorf("no applicable cases selected")
	}
	return cases, nil
}
func reconcile(planned []plannedCase, results []result) error {
	expected := map[string]plannedCase{}
	for _, p := range planned {
		if _, exists := expected[p.ID]; exists {
			return fmt.Errorf("duplicate planned case %s", p.ID)
		}
		expected[p.ID] = p
	}
	if len(expected) == 0 || len(results) != len(expected) {
		return fmt.Errorf("planned %d cases, emitted %d", len(expected), len(results))
	}
	for _, r := range results {
		p, exists := expected[r.ID]
		if !exists {
			return fmt.Errorf("unexpected or duplicate result %s", r.ID)
		}
		delete(expected, r.ID)
		if r.Status == "N/A" && p.NotApplicable != "" && r.Reason == p.NotApplicable {
			continue
		}
		if r.Status != "PASS" || p.NotApplicable != "" {
			return fmt.Errorf("%s: %s: %s", r.ID, r.Status, r.Reason)
		}
	}
	return nil
}
func validateCandidate(c candidate, now time.Time) error {
	if c.Project == "" || c.Version == "" || c.Ecosystem == "" || len(c.Artifacts) == 0 || len(c.Metadata) == 0 {
		return fmt.Errorf("incomplete discovery candidate")
	}
	if c.ObservedAt.IsZero() || c.ObservedAt.After(now.Add(time.Minute)) || !now.Before(c.LatestValidStart) {
		return fmt.Errorf("candidate observation is stale or in the future")
	}
	for _, a := range c.Artifacts {
		if a.Name == "" || a.URL == "" || (len(a.SHA256) != 64 && a.Integrity == "") || a.UploadedAt.IsZero() {
			return fmt.Errorf("incomplete artifact evidence")
		}
	}
	return nil
}
