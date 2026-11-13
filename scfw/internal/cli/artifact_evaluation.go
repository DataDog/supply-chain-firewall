// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// mergeArtifactResults is a mandatory gate, independent of the evaluator's
// backend and warning settings. Manifest mismatches become datadog_policy
// matches so both local and remote reports retain their reason and differences.
func mergeArtifactResults(report *evaluation.ScfwPolicyEvaluationReport, results []pm.ArtifactResult) {
	for _, evidence := range results {
		index := -1
		for i, r := range report.Results {
			if r.Ecosystem == string(evidence.Package.Ecosystem) && r.PackageName == evidence.Package.Name && r.PackageVersion == evidence.Package.Version {
				index = i
				break
			}
		}
		if index < 0 {
			report.Results = append(report.Results, evaluation.PackageEvaluationResult{Ecosystem: string(evidence.Package.Ecosystem), PackageName: evidence.Package.Name, PackageVersion: evidence.Package.Version})
			index = len(report.Results) - 1
		}
		result := &report.Results[index]
		if evidence.Status == pm.ArtifactMatched || evidence.Status == pm.ArtifactNotApplicable {
			if result.Outcome == "" {
				result.Outcome = evaluation.OutcomeAllow
			}
			continue
		}
		report.Outcome = evaluation.OutcomeBlock
		result.Outcome = evaluation.OutcomeBlock
		reason := evidence.Reason
		if reason == "" {
			reason = "artifact-verification"
		}
		if evidence.Status == pm.ArtifactUnverifiable {
			result.Failures = append(result.Failures, evaluation.Failure{Verifier: reason, Error: evidence.Detail})
		} else if reason == "manifest-confusion" {
			result.MatchedPolicy = append(result.MatchedPolicy, evaluation.MatchedPolicy{
				Type:    "datadog_policy",
				Rule:    "manifest confusion : " + evidence.Detail + " are different from the artifact and the registry metadatas",
				Outcome: evaluation.OutcomeBlock,
			})
		} else {
			result.Findings = append(result.Findings, evaluation.Finding{Verifier: reason, Severity: evaluation.SeverityCritical, Text: evidence.Detail})
		}
	}
}
