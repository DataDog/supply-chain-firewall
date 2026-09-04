// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	localevaluation "github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation/local"
)

// evaluationModeVar is the environment variable that selects how SCFW
// evaluates packages and reports outcomes. When set, it must be "datadog" or
// "local"; when unset, the mode is inferred from credential availability.
const evaluationModeVar = "SCFW_MODE"

// evaluationMode is how SCFW evaluates packages and reports outcomes.
type evaluationMode string

const (
	// evaluationModeDatadog evaluates packages and reports outcomes via the
	// Datadog Code Security API, requiring Datadog credentials.
	evaluationModeDatadog evaluationMode = "datadog"
	// evaluationModeLocal evaluates packages via local verifiers against
	// public data sources and reports outcomes to a local log file, requiring
	// no Datadog credentials.
	evaluationModeLocal evaluationMode = "local"
)

// resolveEvaluationMode determines how packages are evaluated and outcomes
// reported: the value of SCFW_MODE when set, else Datadog when both Datadog
// credentials resolve and local verification otherwise.
func resolveEvaluationMode() (evaluationMode, error) {
	if mode := strings.ToLower(os.Getenv(evaluationModeVar)); mode != "" {
		switch mode {
		case string(evaluationModeDatadog):
			return evaluationModeDatadog, nil
		case string(evaluationModeLocal):
			return evaluationModeLocal, nil
		default:
			return "", fmt.Errorf("invalid %s value %q (must be %q or %q)",
				evaluationModeVar, mode, evaluationModeDatadog, evaluationModeLocal)
		}
	}

	if datadogCredentialsFound() {
		return evaluationModeDatadog, nil
	}
	return evaluationModeLocal, nil
}

// datadogCredentialsFound reports whether both the Datadog API key and
// application key resolve from the environment or system keychain. It is
// indirected through a variable so tests can substitute a fake.
var datadogCredentialsFound = func() bool {
	apiKey, _, apiErr := ddapi.ResolveDatadogAPIKey()
	appKey, _, appErr := ddapi.ResolveDatadogAppKey()
	return apiErr == nil && apiKey != "" && appErr == nil && appKey != ""
}

// noteLocalEvaluation tells the user what Datadog Code Security would add, but
// only when SCFW picked local evaluation on its own rather than because
// SCFW_MODE asked for it.
func noteLocalEvaluation(mode evaluationMode) {
	if mode != evaluationModeLocal || os.Getenv(evaluationModeVar) != "" {
		return
	}
	fmt.Fprintln(os.Stderr, "Verifying packages locally. Connect Datadog Code Security for org-wide install "+
		"policies, Datadog's malicious package intelligence, and fleet-wide visibility: "+
		"scfw configure --dd-api-key <key> --dd-app-key <key>")
}

// newEvaluator returns the evaluator for the given evaluation mode.
func newEvaluator(ctx context.Context, mode evaluationMode) (evaluation.Evaluator, error) {
	switch mode {
	case evaluationModeDatadog:
		slog.Debug("evaluating packages via the Datadog Code Security API")
		return ddapi.Evaluator{}, nil
	case evaluationModeLocal:
		slog.Info("evaluating packages with local verifiers")
		return localevaluation.NewEvaluator(ctx)
	default:
		return nil, fmt.Errorf("unknown evaluation mode %q", mode)
	}
}

// newReporter returns the outcome reporter for the given evaluation mode.
func newReporter(mode evaluationMode) evaluation.Reporter {
	switch mode {
	case evaluationModeDatadog:
		slog.Debug("reporting firewall outcomes via the Datadog Code Security API")
		return ddapi.Reporter{}
	case evaluationModeLocal:
		slog.Info("reporting firewall outcomes to the local log file")
		return localevaluation.NewFileReporter()
	default:
		slog.Error("unknown evaluation mode; not reporting firewall outcomes", "mode", mode)
		return nopReporter{}
	}
}

// nopReporter discards reported outcomes.
type nopReporter struct{}

func (nopReporter) ReportFirewallOutcome(
	_ context.Context,
	_ time.Time,
	_ []string,
	_, _, _ string,
	_ evaluation.ScfwPolicyEvaluationReport,
	_ evaluation.Outcome,
) error {
	return nil
}
