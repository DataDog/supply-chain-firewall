// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package local implements local package evaluation and outcome
// reporting: evaluation by running package verifiers against public data
// sources, and reporting of run outcomes to a local JSON Lines log file.
package local

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier/age"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier/ddmalware"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier/list"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier/osv"
)

// maxConcurrentVerifications bounds the number of concurrent verifier calls.
const maxConcurrentVerifications = 8

// newDatadogMaliciousPackagesVerifier is indirected through so tests can
// substitute a fake initializer.
var newDatadogMaliciousPackagesVerifier = func(ctx context.Context) (verifier.Verifier, error) {
	return ddmalware.New(ctx)
}

// Evaluator evaluates installation targets by running the local package
// verifiers against them. Any CRITICAL finding blocks; WARNING findings warn;
// verifier failures are recorded but do not affect the outcome.
type Evaluator struct {
	verifiers []verifier.Verifier
}

// NewEvaluator returns a local Evaluator running SCFW's default verifiers:
// the Datadog malicious-software-packages-dataset, OSV.dev, package age, and
// user-provided findings lists. Default verifiers are best-effort: if one
// cannot be initialized, SCFW logs the failure and continues with the others.
func NewEvaluator(ctx context.Context) (*Evaluator, error) {
	datadogVerifier, err := newDatadogMaliciousPackagesVerifier(ctx)
	verifiers := []verifier.Verifier{
		osv.New(),
		age.New(),
		list.New(),
	}
	if err != nil {
		slog.Warn("failed to initialize Datadog malicious packages verifier", "error", err)
	} else {
		verifiers = append([]verifier.Verifier{datadogVerifier}, verifiers...)
	}
	return &Evaluator{
		verifiers: verifiers,
	}, nil
}

// verification is the outcome of one verifier verifying one package.
type verification struct {
	verifier string
	findings []evaluation.Finding
	err      error
}

// EvaluateInstallTargets verifies every installation target with every
// verifier and aggregates the results into a policy evaluation report.
func (e *Evaluator) EvaluateInstallTargets(ctx context.Context, _ bool, installTargets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
	packages := slices.Collect(installTargets.Items())
	slices.SortFunc(packages, comparePackages)

	// One output cell per (package, verifier) pair, written by its own
	// goroutine and read after Wait, so no locking is needed.
	verifications := make([][]verification, len(packages))
	for i := range packages {
		verifications[i] = make([]verification, len(e.verifiers))
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentVerifications)
	for i, pkg := range packages {
		for j, v := range e.verifiers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				findings, err := v.Verify(ctx, pkg)
				slog.Debug("verified package", "verifier", v.Name(), "package", pkg.Name, "error", err)
				verifications[i][j] = verification{verifier: v.Name(), findings: findings, err: err}
			}()
		}
	}
	wg.Wait()

	results := make([]evaluation.PackageEvaluationResult, 0, len(packages))
	for i, pkg := range packages {
		results = append(results, packageResult(pkg, verifications[i]))
	}
	return evaluation.ScfwPolicyEvaluationReport{
		Outcome: overallOutcome(results),
		Results: results,
	}, nil
}

// packageResult aggregates one package's verifications into its evaluation
// result. Any CRITICAL finding yields BLOCK; WARNING findings yield WARN;
// otherwise the package is ALLOWed. Verification failures are recorded without
// affecting the outcome.
func packageResult(pkg pm.Package, verifications []verification) evaluation.PackageEvaluationResult {
	result := evaluation.PackageEvaluationResult{
		Ecosystem:      string(pkg.Ecosystem),
		PackageName:    pkg.Name,
		PackageVersion: pkg.Version,
		Outcome:        evaluation.OutcomeAllow,
	}

	for _, v := range verifications {
		result.Findings = append(result.Findings, v.findings...)
		if v.err != nil {
			result.Failures = append(result.Failures, evaluation.Failure{
				Verifier: v.verifier,
				Error:    v.err.Error(),
			})
		}
	}

	// Deterministic output regardless of goroutine completion order.
	slices.SortFunc(result.Findings, compareFindings)
	slices.SortFunc(result.Failures, compareFailures)

	result.Outcome = packageOutcome(result)
	return result
}

// packageOutcome resolves a package result's outcome from its findings.
func packageOutcome(result evaluation.PackageEvaluationResult) evaluation.Outcome {
	outcome := evaluation.OutcomeAllow
	for _, finding := range result.Findings {
		if finding.Severity == evaluation.SeverityCritical {
			return evaluation.OutcomeBlock
		}
		outcome = evaluation.OutcomeWarn
	}
	return outcome
}

// overallOutcome resolves a report's outcome from its package results.
func overallOutcome(results []evaluation.PackageEvaluationResult) evaluation.Outcome {
	outcome := evaluation.OutcomeAllow
	for _, result := range results {
		switch result.Outcome {
		case evaluation.OutcomeBlock:
			return evaluation.OutcomeBlock
		case evaluation.OutcomeWarn:
			outcome = evaluation.OutcomeWarn
		}
	}
	return outcome
}

// comparePackages orders packages by ecosystem, name, then version.
func comparePackages(a, b pm.Package) int {
	return strings.Compare(fmt.Sprintf("%s/%s@%s", a.Ecosystem, a.Name, a.Version),
		fmt.Sprintf("%s/%s@%s", b.Ecosystem, b.Name, b.Version))
}

// compareFindings orders findings by severity, then verifier, then text.
func compareFindings(a, b evaluation.Finding) int {
	if a.Severity != b.Severity {
		if a.Severity == evaluation.SeverityCritical {
			return -1
		}
		return 1
	}
	if c := strings.Compare(a.Verifier, b.Verifier); c != 0 {
		return c
	}
	return strings.Compare(a.Text, b.Text)
}

// compareFailures orders failures by verifier, then error.
func compareFailures(a, b evaluation.Failure) int {
	if c := strings.Compare(a.Verifier, b.Verifier); c != 0 {
		return c
	}
	return strings.Compare(a.Error, b.Error)
}
