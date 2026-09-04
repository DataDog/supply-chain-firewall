// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	localevaluation "github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation/local"
)

// withoutDatadogCredentials clears any ambient Datadog credential environment
// variables and disables keychain lookup for the duration of a test.
func withoutDatadogCredentials(t *testing.T) {
	t.Helper()
	for _, name := range []string{"DD_API_KEY", "DD_APP_KEY"} {
		t.Setenv(name, "")
	}
	original := datadogCredentialsFound
	datadogCredentialsFound = func() bool { return false }
	t.Cleanup(func() { datadogCredentialsFound = original })
}

// withDatadogCredentials simulates resolvable Datadog credentials for the
// duration of a test.
func withDatadogCredentials(t *testing.T) {
	t.Helper()
	original := datadogCredentialsFound
	datadogCredentialsFound = func() bool { return true }
	t.Cleanup(func() { datadogCredentialsFound = original })
}

func TestResolveEvaluationMode(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		credentialsOK bool
		want          evaluationMode
		wantErr       bool
	}{
		{name: "explicit datadog", mode: "datadog", want: evaluationModeDatadog},
		{name: "explicit local", mode: "local", want: evaluationModeLocal},
		{name: "explicit mode is case-insensitive", mode: "LOCAL", want: evaluationModeLocal},
		{name: "invalid mode", mode: "cloud", wantErr: true},
		{name: "credentials imply datadog", credentialsOK: true, want: evaluationModeDatadog},
		{name: "missing credentials imply local", want: evaluationModeLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withoutDatadogCredentials(t)
			if tt.credentialsOK {
				withDatadogCredentials(t)
			}
			t.Setenv(evaluationModeVar, tt.mode)

			got, err := resolveEvaluationMode()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveEvaluationMode() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEvaluationMode() returned unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveEvaluationMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveEvaluationModePrefersEnvOverCredentials(t *testing.T) {
	withoutDatadogCredentials(t)
	withDatadogCredentials(t)
	t.Setenv(evaluationModeVar, "local")

	if got, err := resolveEvaluationMode(); err != nil || got != evaluationModeLocal {
		t.Errorf("resolveEvaluationMode() = %q (err %v), want local despite credentials", got, err)
	}
}

func TestNewEvaluatorAndReporterForDatadog(t *testing.T) {
	evaluator, err := newEvaluator(context.Background(), evaluationModeDatadog)
	if err != nil {
		t.Fatalf("newEvaluator() returned unexpected error: %v", err)
	}
	if _, ok := evaluator.(ddapi.Evaluator); !ok {
		t.Errorf("newEvaluator(datadog) = %T, want ddapi.Evaluator", evaluator)
	}

	if _, ok := newReporter(evaluationModeDatadog).(ddapi.Reporter); !ok {
		t.Errorf("newReporter(datadog) = %T, want ddapi.Reporter", newReporter(evaluationModeDatadog))
	}
}

func TestNewReporterForLocalWritesToLocalFile(t *testing.T) {
	t.Setenv("SCFW_HOME", t.TempDir())
	t.Setenv("SCFW_LOG_FILE", "")
	reporter := newReporter(evaluationModeLocal)
	if _, ok := reporter.(*localevaluation.FileReporter); !ok {
		t.Errorf("newReporter(local) = %T, want *local.FileReporter", reporter)
	}
}
