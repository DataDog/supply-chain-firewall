// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package evaluation defines Supply Chain Firewall's policy evaluation and
// reporting domain: the shared types describing package evaluation outcomes
// and reports, and the interfaces that concrete evaluation and
// reporting backends implement.
package evaluation

import (
	"context"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// Outcome is the decision for a MatchedPolicy, a PackageEvaluationResult, or a
// whole ScfwPolicyEvaluationReport. Org policy rules only ever decide block or
// allow; warn/error can only come from Datadog advisory-db matches.
type Outcome string

const (
	OutcomeAllow Outcome = "ALLOW"
	OutcomeBlock Outcome = "BLOCK"
	OutcomeWarn  Outcome = "WARN"
	OutcomeError Outcome = "ERROR"
)

// MatchedPolicy is one policy source (org and/or Datadog) that contributed to a
// PackageEvaluationResult.
type MatchedPolicy struct {
	Type    string  `json:"type"`
	Rule    string  `json:"rule,omitempty"`
	Outcome Outcome `json:"outcome"`
}

// Failure records a verifier that could not be evaluated for a package.
type Failure struct {
	Verifier string `json:"verifier"`
	Error    string `json:"error"`
}

// PackageEvaluationResult is the decision for one evaluated package.
type PackageEvaluationResult struct {
	Ecosystem      string          `json:"ecosystem"`
	PackageName    string          `json:"package_name"`
	PackageVersion string          `json:"package_version"`
	Outcome        Outcome         `json:"outcome"`
	MatchedPolicy  []MatchedPolicy `json:"matched_policy,omitempty"`
	Failures       []Failure       `json:"failures,omitempty"`
}

// ScfwPolicyEvaluationReport is the result of evaluating a set of package
// installation targets.
type ScfwPolicyEvaluationReport struct {
	Outcome Outcome                   `json:"outcome"`
	Results []PackageEvaluationResult `json:"results"`
}

// Evaluator evaluates a set of package installation targets against policy
// and returns the resulting evaluation report.
type Evaluator interface {
	EvaluateInstallTargets(ctx context.Context, isInteractive bool, installTargets *pm.Set[pm.Package]) (ScfwPolicyEvaluationReport, error)
}

// Reporter reports the firewall's ultimate decision for a completed run.
// resolvedOutcome is the outcome actually acted on (ALLOW or BLOCK): a WARN
// (or ERROR, which is coerced to WARN) returned by evaluation must be
// resolved locally before it is reported.
type Reporter interface {
	ReportFirewallOutcome(
		ctx context.Context,
		installTimestamp time.Time,
		command []string,
		packageManagerName, executable, repository string,
		evaluationReport ScfwPolicyEvaluationReport,
		resolvedOutcome Outcome,
	) error
}
