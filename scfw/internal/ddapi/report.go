// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Code Security API endpoint for submitting SCFW run reports.
const ddCodeSecurityAPIEndpoint = "api/v2/static-analysis-sca/scfw/report"

type ddReportRequest struct {
	Data ddReportRequestData `json:"data"`
}

type ddReportRequestData struct {
	Type       string             `json:"type"`
	ID         string             `json:"id"`
	Attributes ddReportAttributes `json:"attributes"`
}

type ddReportAttributes struct {
	Cwd              string            `json:"cwd"`
	Executable       string            `json:"executable"`
	Hostname         string            `json:"hostname"`
	InstallTimestamp string            `json:"install_timestamp"`
	PackageManager   string            `json:"package_manager"`
	Command          string            `json:"command"`
	Outcome          string            `json:"outcome"`
	Reports          []ddPackageReport `json:"reports"`
}

type ddPackageReport struct {
	Ecosystem string      `json:"ecosystem"`
	Package   string      `json:"package"`
	Version   string      `json:"version"`
	Warning   bool        `json:"warning"`
	Findings  []ddFinding `json:"findings"`
}

type ddFinding struct {
	Verifier string `json:"verifier"`
	Finding  string `json:"finding"`
}

// Report the firewall's ultimate decision to the Code Security API. resolvedOutcome is
// the outcome actually acted on (ALLOW or BLOCK): the /report endpoint does not accept
// WARN, so a WARN (or ERROR, which is coerced to WARN) returned by /evaluate must be
// resolved locally before it's reported here.
func ReportFirewallOutcome(
	ctx context.Context,
	installTimestamp time.Time,
	command []string,
	packageManagerName, executable string,
	evaluationReport ScfwPolicyEvaluationReport,
	resolvedOutcome Outcome,
) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to determine hostname: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to determine working directory: %w", err)
	}
	requestID, err := newRequestID()
	if err != nil {
		return fmt.Errorf("failed to generate report request ID: %w", err)
	}

	payload := ddReportRequest{
		Data: ddReportRequestData{
			Type: "scfw-report-request",
			ID:   requestID,
			Attributes: ddReportAttributes{
				Cwd:              cwd,
				Executable:       executable,
				Hostname:         hostname,
				InstallTimestamp: installTimestamp.Format(time.RFC3339),
				PackageManager:   packageManagerName,
				Command:          strings.Join(command, " "),
				Outcome:          string(resolvedOutcome),
				Reports:          packageReports(reportedResults(evaluationReport, resolvedOutcome)),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Code Security API report payload: %w", err)
	}

	_, err = postDatadogAPI(ctx, ddCodeSecurityAPIEndpoint, body)
	return err
}

// reportedResults selects which Results to report for a resolved outcome. Results are
// reported as-is unless /evaluate returned WARN/ERROR and that was resolved locally to
// BLOCK, in which case only the Results that caused it are reported.
func reportedResults(evaluationReport ScfwPolicyEvaluationReport, resolvedOutcome Outcome) []PackageEvaluationResult {
	if resolvedOutcome == OutcomeAllow || evaluationReport.Outcome == OutcomeBlock {
		return evaluationReport.Results
	}

	filtered := make([]PackageEvaluationResult, 0, len(evaluationReport.Results))
	for _, result := range evaluationReport.Results {
		if result.Outcome == evaluationReport.Outcome {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

// Generate package reports for a set of policy evaluation results.
func packageReports(results []PackageEvaluationResult) []ddPackageReport {
	reports := make([]ddPackageReport, 0, len(results))
	for _, result := range results {
		reports = append(reports, ddPackageReport{
			Ecosystem: result.Ecosystem,
			Package:   result.PackageName,
			Version:   result.PackageVersion,
			Warning:   result.Outcome == OutcomeWarn,
			Findings:  packageFindings(result),
		})
	}
	return reports
}

// Generate the findings for a single package evaluation result, combining its matched
// policies and any verifier failures.
func packageFindings(result PackageEvaluationResult) []ddFinding {
	findings := make([]ddFinding, 0, len(result.MatchedPolicy)+len(result.Failures))
	for _, policy := range result.MatchedPolicy {
		findings = append(findings, ddFinding{Verifier: policy.Type, Finding: policy.Rule})
	}
	for _, f := range result.Failures {
		findings = append(findings, ddFinding{Verifier: f.Verifier, Finding: f.Error})
	}
	return findings
}
