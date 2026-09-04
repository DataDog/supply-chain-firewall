// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package local

import (
	"context"
	"errors"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier"
)

// fakeVerifier is a verifier whose findings and error are fixed at
// construction.
type fakeVerifier struct {
	name     string
	findings []evaluation.Finding
	err      error
}

func (v fakeVerifier) Name() string { return v.name }

func (v fakeVerifier) Verify(context.Context, pm.Package) ([]evaluation.Finding, error) {
	return v.findings, v.err
}

// packageKey identifies a package in evaluation assertions.
func packageKey(pkg pm.Package) string {
	return string(pkg.Ecosystem) + "/" + pkg.Name + "@" + pkg.Version
}

func TestNewEvaluatorContinuesWhenDefaultVerifierCannotInitialize(t *testing.T) {
	original := newDatadogMaliciousPackagesVerifier
	newDatadogMaliciousPackagesVerifier = func(context.Context) (verifier.Verifier, error) {
		return nil, errors.New("dataset unavailable")
	}
	t.Cleanup(func() { newDatadogMaliciousPackagesVerifier = original })

	e, err := NewEvaluator(context.Background())
	if err != nil {
		t.Fatalf("NewEvaluator() returned unexpected error: %v", err)
	}
	if len(e.verifiers) != 3 {
		t.Fatalf("len(verifiers) = %d, want 3 default verifiers after skipping Datadog malware verifier", len(e.verifiers))
	}
	for _, v := range e.verifiers {
		if v.Name() == "DatadogMaliciousPackagesVerifier" {
			t.Fatal("Datadog malicious packages verifier was included despite initialization failure")
		}
	}
}

func TestEvaluatorAggregatesVerifierResults(t *testing.T) {
	tests := []struct {
		name        string
		verifiers   []verifier.Verifier
		wantOutcome evaluation.Outcome
	}{
		{
			name:        "allow when clean",
			verifiers:   []verifier.Verifier{fakeVerifier{name: "clean"}},
			wantOutcome: evaluation.OutcomeAllow,
		},
		{
			name: "block on any critical finding",
			verifiers: []verifier.Verifier{
				fakeVerifier{name: "warns", findings: []evaluation.Finding{{Verifier: "warns", Severity: evaluation.SeverityWarning, Text: "w"}}},
				fakeVerifier{name: "blocks", findings: []evaluation.Finding{{Verifier: "blocks", Severity: evaluation.SeverityCritical, Text: "c"}}},
			},
			wantOutcome: evaluation.OutcomeBlock,
		},
		{
			name: "warn on warning findings",
			verifiers: []verifier.Verifier{
				fakeVerifier{name: "warns", findings: []evaluation.Finding{{Verifier: "warns", Severity: evaluation.SeverityWarning, Text: "w"}}},
			},
			wantOutcome: evaluation.OutcomeWarn,
		},
		{
			name: "allow despite verification failures",
			verifiers: []verifier.Verifier{
				fakeVerifier{name: "fails", err: errFakeVerification{}},
			},
			wantOutcome: evaluation.OutcomeAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Evaluator{verifiers: tt.verifiers}
			installTargets := pm.NewSet(
				pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"},
				pm.Package{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.17.0"},
			)

			report, err := e.EvaluateInstallTargets(context.Background(), true, installTargets)
			if err != nil {
				t.Fatalf("EvaluateInstallTargets() returned unexpected error: %v", err)
			}
			if report.Outcome != tt.wantOutcome {
				t.Errorf("report.Outcome = %q, want %q", report.Outcome, tt.wantOutcome)
			}
			if len(report.Results) != installTargets.Len() {
				t.Errorf("len(report.Results) = %d, want %d", len(report.Results), installTargets.Len())
			}
			for _, result := range report.Results {
				if result.Outcome != tt.wantOutcome {
					t.Errorf("package %s: outcome = %q, want %q",
						packageKey(pm.Package{Ecosystem: ecosystem.Ecosystem(result.Ecosystem), Name: result.PackageName, Version: result.PackageVersion}),
						result.Outcome, tt.wantOutcome)
				}
			}
		})
	}
}

func TestEvaluatorBlocksOnlyOffendingPackages(t *testing.T) {
	e := &Evaluator{verifiers: []verifier.Verifier{
		newFuncVerifier("blocker", func(pkg pm.Package) ([]evaluation.Finding, error) {
			if pkg.Name == "evil" {
				return []evaluation.Finding{{Verifier: "blocker", Severity: evaluation.SeverityCritical, Text: "malicious"}}, nil
			}
			return nil, nil
		}),
	}}
	installTargets := pm.NewSet(
		pm.Package{Ecosystem: ecosystem.NPM, Name: "evil", Version: "1.0.0"},
		pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"},
	)

	report, err := e.EvaluateInstallTargets(context.Background(), false, installTargets)
	if err != nil {
		t.Fatalf("EvaluateInstallTargets() returned unexpected error: %v", err)
	}
	if report.Outcome != evaluation.OutcomeBlock {
		t.Fatalf("report.Outcome = %q, want BLOCK", report.Outcome)
	}

	byKey := map[string]evaluation.PackageEvaluationResult{}
	for _, result := range report.Results {
		byKey[result.PackageName] = result
	}
	if byKey["evil"].Outcome != evaluation.OutcomeBlock {
		t.Errorf("evil outcome = %q, want BLOCK", byKey["evil"].Outcome)
	}
	if byKey["left-pad"].Outcome != evaluation.OutcomeAllow {
		t.Errorf("left-pad outcome = %q, want ALLOW", byKey["left-pad"].Outcome)
	}
}

func TestEvaluatorRecordsFailuresWithVerifierNames(t *testing.T) {
	e := &Evaluator{verifiers: []verifier.Verifier{
		fakeVerifier{name: "failing", err: errFakeVerification{}},
	}}
	installTargets := pm.NewSet(pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"})

	report, err := e.EvaluateInstallTargets(context.Background(), true, installTargets)
	if err != nil {
		t.Fatalf("EvaluateInstallTargets() returned unexpected error: %v", err)
	}
	if report.Outcome != evaluation.OutcomeAllow {
		t.Fatalf("report.Outcome = %q, want ALLOW", report.Outcome)
	}
	result := report.Results[0]
	if len(result.Failures) != 1 || result.Failures[0].Verifier != "failing" {
		t.Errorf("Failures = %+v, want one entry attributed to the failing verifier", result.Failures)
	}
}

func TestPackageOutcome(t *testing.T) {
	tests := []struct {
		name   string
		result evaluation.PackageEvaluationResult
		want   evaluation.Outcome
	}{
		{
			name:   "clean",
			result: evaluation.PackageEvaluationResult{},
			want:   evaluation.OutcomeAllow,
		},
		{
			name: "critical finding blocks",
			result: evaluation.PackageEvaluationResult{Findings: []evaluation.Finding{
				{Severity: evaluation.SeverityWarning},
				{Severity: evaluation.SeverityCritical},
			}},
			want: evaluation.OutcomeBlock,
		},
		{
			name: "warning findings warn",
			result: evaluation.PackageEvaluationResult{Findings: []evaluation.Finding{
				{Severity: evaluation.SeverityWarning},
			}},
			want: evaluation.OutcomeWarn,
		},
		{
			name:   "failures allow",
			result: evaluation.PackageEvaluationResult{Failures: []evaluation.Failure{{Verifier: "v", Error: "e"}}},
			want:   evaluation.OutcomeAllow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packageOutcome(tt.result); got != tt.want {
				t.Errorf("packageOutcome() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOverallOutcome(t *testing.T) {
	tests := []struct {
		name    string
		results []evaluation.PackageEvaluationResult
		want    evaluation.Outcome
	}{
		{
			name:    "empty",
			results: nil,
			want:    evaluation.OutcomeAllow,
		},
		{
			name:    "all allow",
			results: []evaluation.PackageEvaluationResult{{Outcome: evaluation.OutcomeAllow}},
			want:    evaluation.OutcomeAllow,
		},
		{
			name: "warn",
			results: []evaluation.PackageEvaluationResult{
				{Outcome: evaluation.OutcomeAllow},
				{Outcome: evaluation.OutcomeWarn},
			},
			want: evaluation.OutcomeWarn,
		},
		{
			name: "block wins",
			results: []evaluation.PackageEvaluationResult{
				{Outcome: evaluation.OutcomeWarn},
				{Outcome: evaluation.OutcomeBlock},
			},
			want: evaluation.OutcomeBlock,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := overallOutcome(tt.results); got != tt.want {
				t.Errorf("overallOutcome() = %q, want %q", got, tt.want)
			}
		})
	}
}

// errFakeVerification is a sentinel verification error.
type errFakeVerification struct{}

func (errFakeVerification) Error() string { return "verification failed" }

// verifyFn adapts a function to the Verifier interface.
type verifyFn func(pm.Package) ([]evaluation.Finding, error)

type funcVerifier struct {
	name string
	fn   verifyFn
}

func (v funcVerifier) Name() string { return v.name }

func (v funcVerifier) Verify(_ context.Context, pkg pm.Package) ([]evaluation.Finding, error) {
	return v.fn(pkg)
}

// newFuncVerifier wraps fn in a Verifier reporting the given name.
func newFuncVerifier(name string, fn verifyFn) verifier.Verifier {
	return funcVerifier{name: name, fn: fn}
}
