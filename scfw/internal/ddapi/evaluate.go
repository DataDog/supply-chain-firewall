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

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// Code Security API endpoint for evaluating installation targets against policy.
const ddPolicyEvaluateEndpoint = "api/v2/static-analysis-sca/scfw/policy/evaluate"

// Evaluator evaluates installation targets against policy via the Datadog
// Code Security API. It implements evaluation.Evaluator.
type Evaluator struct{}

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

type postScfwPolicyEvaluateResponse struct {
	Data postScfwPolicyEvaluateResponseData `json:"data"`
}

type postScfwPolicyEvaluateResponseData struct {
	ID         string                                `json:"id,omitempty"`
	Attributes evaluation.ScfwPolicyEvaluationReport `json:"attributes"`
}

// EvaluateInstallTargets evaluates the given installation targets against
// policy via the Code Security API and returns the evaluation report.
func (Evaluator) EvaluateInstallTargets(ctx context.Context, isInteractive bool, installTargets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
	requestID, err := newRequestID()
	if err != nil {
		return evaluation.ScfwPolicyEvaluationReport{}, fmt.Errorf("failed to generate policy evaluation request ID: %w", err)
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
		return evaluation.ScfwPolicyEvaluationReport{}, fmt.Errorf("failed to marshal policy evaluation request payload: %w", err)
	}

	respBody, err := postDatadogAPI(ctx, ddPolicyEvaluateEndpoint, body)
	if err != nil {
		return evaluation.ScfwPolicyEvaluationReport{}, err
	}

	var result postScfwPolicyEvaluateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return evaluation.ScfwPolicyEvaluationReport{}, fmt.Errorf("failed to decode policy evaluation response: %w", err)
	}

	return result.Data.Attributes, nil
}
