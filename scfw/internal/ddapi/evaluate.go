// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// Code Security API endpoint for evaluating installation targets against policy.
const ddPolicyEvaluateEndpoint = "api/v2/static-analysis-sca/scfw/policy/evaluate"

type postScfwPolicyEvaluateRequest struct {
	Data postScfwPolicyEvaluateRequestData `json:"data"`
}

type postScfwPolicyEvaluateRequestData struct {
	Type       string                                  `json:"type"`
	ID         string                                  `json:"id,omitempty"`
	Attributes postScfwPolicyEvaluateRequestAttributes `json:"attributes"`
}

type postScfwPolicyEvaluateRequestAttributes struct {
	Packages      []pm.Package `json:"packages"`
	IsInteractive bool         `json:"is_interactive"`
}

// Outcome is the decision for a matchedPolicy, a packageEvaluationResult, or a whole
// postScfwPolicyEvaluateResponse. Org policy rules only ever decide block or allow;
// warn/error can only come from Datadog advisory-db matches.
type Outcome string

const (
	OutcomeAllow Outcome = "ALLOW"
	OutcomeBlock Outcome = "BLOCK"
	OutcomeWarn  Outcome = "WARN"
	OutcomeError Outcome = "ERROR"
)

type postScfwPolicyEvaluateResponse struct {
	Data postScfwPolicyEvaluateResponseData `json:"data"`
}

type postScfwPolicyEvaluateResponseData struct {
	ID         string                     `json:"id,omitempty"`
	Attributes ScfwPolicyEvaluationReport `json:"attributes"`
}

type ScfwPolicyEvaluationReport struct {
	Outcome Outcome                   `json:"outcome"`
	Results []PackageEvaluationResult `json:"results"`
}

// packageEvaluationResult is the decision for one evaluated package.
type PackageEvaluationResult struct {
	Ecosystem      string          `json:"ecosystem"`
	PackageName    string          `json:"package_name"`
	PackageVersion string          `json:"package_version"`
	Outcome        Outcome         `json:"outcome"`
	MatchedPolicy  []matchedPolicy `json:"matched_policy,omitempty"`
	Failures       []failure       `json:"failures,omitempty"`
}

// failure records a verifier that could not be evaluated for a package.
type failure struct {
	Verifier string `json:"verifier"`
	Error    string `json:"error"`
}

// matchedPolicy is one policy source (org and/or datadog) that contributed to a
// packageEvaluationResult.
type matchedPolicy struct {
	Type    string  `json:"type"`
	Rule    string  `json:"rule,omitempty"`
	Outcome Outcome `json:"outcome"`
}

func EvaluateInstallTargets(ctx context.Context, isInteractive bool, installTargets *pm.Set[pm.Package]) (ScfwPolicyEvaluationReport, error) {
	requestID, err := newRequestID()
	if err != nil {
		return ScfwPolicyEvaluationReport{}, fmt.Errorf("failed to generate policy evaluation request ID: %w", err)
	}

	payload := postScfwPolicyEvaluateRequest{
		Data: postScfwPolicyEvaluateRequestData{
			Type: "scfw-policy-evaluate-request",
			ID:   requestID,
			Attributes: postScfwPolicyEvaluateRequestAttributes{
				Packages:      slices.Collect(installTargets.Items()),
				IsInteractive: isInteractive,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return ScfwPolicyEvaluationReport{}, fmt.Errorf("failed to marshal policy evaluation request payload: %w", err)
	}

	respBody, err := postDatadogAPI(ctx, ddPolicyEvaluateEndpoint, body)
	if err != nil {
		return ScfwPolicyEvaluationReport{}, err
	}

	var result postScfwPolicyEvaluateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return ScfwPolicyEvaluationReport{}, fmt.Errorf("failed to decode policy evaluation response: %w", err)
	}

	return result.Data.Attributes, nil
}
