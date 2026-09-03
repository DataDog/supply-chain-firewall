// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDDReportAttributesMarshalsRepository(t *testing.T) {
	attributes := ddReportAttributes{Repository: "https://example.com/acme/project.git"}

	body, err := json.Marshal(attributes)
	if err != nil {
		t.Fatalf("json.Marshal() returned unexpected error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal() returned unexpected error: %v", err)
	}
	if got["repository"] != attributes.Repository {
		t.Fatalf("repository = %v, want %q", got["repository"], attributes.Repository)
	}
}

func TestPackageReports(t *testing.T) {
	evaluationReport := ScfwPolicyEvaluationReport{
		Outcome: OutcomeBlock,
		Results: []PackageEvaluationResult{
			{
				Ecosystem:      "PyPI",
				PackageName:    "requests",
				PackageVersion: "2.31.0",
				Outcome:        OutcomeBlock,
				MatchedPolicy: []matchedPolicy{
					{Type: "org_policy", Rule: "no-requests", Outcome: OutcomeBlock},
				},
			},
			{
				Ecosystem:      "npm",
				PackageName:    "left-pad",
				PackageVersion: "1.3.0",
				Outcome:        OutcomeWarn,
				Failures: []failure{
					{Verifier: "datadog_policy", Error: "advisory-db lookup timed out"},
				},
			},
		},
	}

	got := packageReports(evaluationReport.Results)

	want := []ddPackageReport{
		{
			Ecosystem: "PyPI",
			Package:   "requests",
			Version:   "2.31.0",
			Warning:   false,
			Failures:  []ddFailure{},
			MatchedPolicies: []ddMatchedPolicy{
				{Type: "org_policy", Rule: "no-requests", Outcome: "BLOCK"},
			},
		},
		{
			Ecosystem: "npm",
			Package:   "left-pad",
			Version:   "1.3.0",
			Warning:   true,
			Failures: []ddFailure{
				{Verifier: "datadog_policy", Error: "advisory-db lookup timed out"},
			},
			MatchedPolicies: []ddMatchedPolicy{},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("packageReports() = %+v, want %+v", got, want)
	}
}

func TestPackageReports_DoesNotFilterResults(t *testing.T) {
	// packageReports reports whatever results it's given, regardless of their outcome;
	// callers (reportedResults) are responsible for any filtering.
	results := []PackageEvaluationResult{
		{Ecosystem: "PyPI", PackageName: "six", PackageVersion: "1.17.0", Outcome: OutcomeAllow},
	}

	got := packageReports(results)
	if len(got) != 1 {
		t.Fatalf("len(packageReports()) = %d, want 1", len(got))
	}
}

func TestReportedResults(t *testing.T) {
	warnResult := PackageEvaluationResult{Ecosystem: "npm", PackageName: "left-pad", PackageVersion: "1.3.0", Outcome: OutcomeWarn}
	allowResult := PackageEvaluationResult{Ecosystem: "PyPI", PackageName: "six", PackageVersion: "1.17.0", Outcome: OutcomeAllow}
	errorResult := PackageEvaluationResult{Ecosystem: "npm", PackageName: "flaky", PackageVersion: "1.0.0", Outcome: OutcomeError}

	tests := []struct {
		name             string
		evaluationReport ScfwPolicyEvaluationReport
		resolvedOutcome  Outcome
		want             []PackageEvaluationResult
	}{
		{
			name:             "ALLOW from evaluate: reported as-is",
			evaluationReport: ScfwPolicyEvaluationReport{Outcome: OutcomeAllow, Results: []PackageEvaluationResult{allowResult}},
			resolvedOutcome:  OutcomeAllow,
			want:             []PackageEvaluationResult{allowResult},
		},
		{
			name:             "BLOCK from evaluate: reported as-is, even if a result's own outcome differs",
			evaluationReport: ScfwPolicyEvaluationReport{Outcome: OutcomeBlock, Results: []PackageEvaluationResult{allowResult}},
			resolvedOutcome:  OutcomeBlock,
			want:             []PackageEvaluationResult{allowResult},
		},
		{
			name:             "WARN from evaluate, resolved to ALLOW: reported as-is",
			evaluationReport: ScfwPolicyEvaluationReport{Outcome: OutcomeWarn, Results: []PackageEvaluationResult{allowResult, warnResult}},
			resolvedOutcome:  OutcomeAllow,
			want:             []PackageEvaluationResult{allowResult, warnResult},
		},
		{
			name:             "WARN from evaluate, resolved to BLOCK: only the WARN results",
			evaluationReport: ScfwPolicyEvaluationReport{Outcome: OutcomeWarn, Results: []PackageEvaluationResult{allowResult, warnResult}},
			resolvedOutcome:  OutcomeBlock,
			want:             []PackageEvaluationResult{warnResult},
		},
		{
			name:             "ERROR from evaluate, resolved to BLOCK: only the ERROR results",
			evaluationReport: ScfwPolicyEvaluationReport{Outcome: OutcomeError, Results: []PackageEvaluationResult{allowResult, errorResult}},
			resolvedOutcome:  OutcomeBlock,
			want:             []PackageEvaluationResult{errorResult},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportedResults(tt.evaluationReport, tt.resolvedOutcome); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reportedResults() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPackageFailures(t *testing.T) {
	tests := []struct {
		name   string
		result PackageEvaluationResult
		want   []ddFailure
	}{
		{
			name:   "no failures",
			result: PackageEvaluationResult{},
			want:   []ddFailure{},
		},
		{
			name: "failures only",
			result: PackageEvaluationResult{
				Failures: []failure{{Verifier: "datadog_policy", Error: "timed out"}},
			},
			want: []ddFailure{{Verifier: "datadog_policy", Error: "timed out"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packageFailures(tt.result); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("packageFailures() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPackageMatchedPolicies(t *testing.T) {
	tests := []struct {
		name   string
		result PackageEvaluationResult
		want   []ddMatchedPolicy
	}{
		{
			name:   "no matched policy",
			result: PackageEvaluationResult{},
			want:   []ddMatchedPolicy{},
		},
		{
			name: "matched policy only",
			result: PackageEvaluationResult{
				MatchedPolicy: []matchedPolicy{{Type: "org_policy", Rule: "no-foo", Outcome: OutcomeBlock}},
			},
			want: []ddMatchedPolicy{{Type: "org_policy", Rule: "no-foo", Outcome: "BLOCK"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packageMatchedPolicies(tt.result); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("packageMatchedPolicies() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
