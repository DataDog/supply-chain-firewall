// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/DataDog/scfw/scfw/internal/ddapi"
)

func TestDecideFirewallAction(t *testing.T) {
	tests := []struct {
		outcome ddapi.Outcome
		want    ddapi.Outcome
	}{
		{ddapi.OutcomeAllow, ddapi.OutcomeAllow},
		{ddapi.OutcomeBlock, ddapi.OutcomeBlock},
		{ddapi.OutcomeWarn, ddapi.OutcomeBlock},
		{ddapi.OutcomeError, ddapi.OutcomeBlock},
		{ddapi.Outcome("UNKNOWN"), ddapi.OutcomeBlock},
	}

	for _, tt := range tests {
		if got := decideFirewallAction(false, tt.outcome); got != tt.want {
			t.Errorf("decideFirewallAction(false, %q) = %q, want %q", tt.outcome, got, tt.want)
		}
	}
}

func TestResolveOnWarning(t *testing.T) {
	tests := []struct {
		name           string
		allowOnWarning bool
		blockOnWarning bool
		env            string
		wantOnWarning  ddapi.Outcome
		wantErr        bool
	}{
		{name: "no flags no env", wantOnWarning: ddapi.OutcomeWarn},
		{name: "allow flag", allowOnWarning: true, wantOnWarning: ddapi.OutcomeAllow},
		{name: "block flag", blockOnWarning: true, wantOnWarning: ddapi.OutcomeBlock},
		{name: "env allow overrides block flag", blockOnWarning: true, env: "allow", wantOnWarning: ddapi.OutcomeAllow},
		{name: "env block overrides allow flag", allowOnWarning: true, env: "block", wantOnWarning: ddapi.OutcomeBlock},
		{name: "env value is case-insensitive", env: "ALLOW", wantOnWarning: ddapi.OutcomeAllow},
		{name: "invalid env value", env: "nonsense", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowOnWarning = tt.allowOnWarning
			blockOnWarning = tt.blockOnWarning
			onWarning = ddapi.OutcomeWarn
			if tt.env != "" {
				os.Setenv(onWarningVar, tt.env)
			} else {
				os.Unsetenv(onWarningVar)
			}
			t.Cleanup(func() {
				allowOnWarning = false
				blockOnWarning = false
				onWarning = ddapi.OutcomeWarn
				os.Unsetenv(onWarningVar)
			})

			err := resolveOnWarning()
			if tt.wantErr {
				if err == nil {
					t.Fatal("resolveOnWarning() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveOnWarning() returned unexpected error: %v", err)
			}
			if onWarning != tt.wantOnWarning {
				t.Errorf("onWarning = %q, want %q", onWarning, tt.wantOnWarning)
			}
		})
	}
}

func TestParseInstallConfirmation(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  ddapi.Outcome
	}{
		{name: "y", input: "y\n", want: ddapi.OutcomeAllow},
		{name: "yes", input: "yes\n", want: ddapi.OutcomeAllow},
		{name: "uppercase Y", input: "Y\n", want: ddapi.OutcomeAllow},
		{name: "mixed case Yes", input: "Yes\n", want: ddapi.OutcomeAllow},
		{name: "trims surrounding whitespace", input: "  yes  \n", want: ddapi.OutcomeAllow},
		{name: "n", input: "n\n", want: ddapi.OutcomeBlock},
		{name: "empty line", input: "\n", want: ddapi.OutcomeBlock},
		{name: "garbage", input: "sure\n", want: ddapi.OutcomeBlock},
		{name: "no trailing newline (read error)", input: "yes", want: ddapi.OutcomeBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseInstallConfirmation(strings.NewReader(tt.input)); got != tt.want {
				t.Errorf("parseInstallConfirmation(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRunCmd_AllowAndBlockOnWarningAreMutuallyExclusive(t *testing.T) {
	t.Cleanup(func() {
		allowOnWarning = false
		blockOnWarning = false
		runCmd.Flags().Set("allow-on-warning", "false")
		runCmd.Flags().Set("block-on-warning", "false")
	})

	if err := runCmd.ParseFlags([]string{"--allow-on-warning", "--block-on-warning"}); err != nil {
		t.Fatalf("ParseFlags() returned unexpected error: %v", err)
	}
	if err := runCmd.ValidateFlagGroups(); err == nil {
		t.Fatal("ValidateFlagGroups() = nil error, want error for mutually exclusive flags")
	}
}

func TestRunCmd_RejectsFlagLikeValues(t *testing.T) {
	t.Cleanup(func() {
		executable = ""
		runCmd.Flags().Set("executable", "")
		runCmd.Flags().Lookup("executable").Changed = false
		runCmd.Flags().Lookup("error-on-block").Changed = false
	})

	// A missing value for --executable lets it swallow --error-on-block as its value.
	if err := runCmd.ParseFlags([]string{"--executable", "--error-on-block"}); err != nil {
		t.Fatalf("ParseFlags() returned unexpected error: %v", err)
	}
	if err := rejectFlagLikeValues(runCmd); err == nil {
		t.Fatal("rejectFlagLikeValues(runCmd) = nil error, want error for --executable swallowing --error-on-block")
	}
}

// resetRunCmd restores runCmd's flag-parsing state (bound vars, pflag's
// per-flag Changed bit, and silence settings) after a test drives it through
// actual Cobra parsing via Execute, so later tests still see the package's
// normal zero-value defaults.
func resetRunCmd(t *testing.T) {
	t.Helper()
	origSilenceUsage, origSilenceErrors := runCmd.SilenceUsage, runCmd.SilenceErrors
	runCmd.SilenceUsage, runCmd.SilenceErrors = true, true

	t.Cleanup(func() {
		runCmd.SilenceUsage, runCmd.SilenceErrors = origSilenceUsage, origSilenceErrors
		allowOnWarning, blockOnWarning, errorOnBlock, executable = false, false, false, ""
		for _, name := range []string{"allow-on-warning", "block-on-warning", "error-on-block", "executable"} {
			runCmd.Flags().Lookup(name).Changed = false
		}
	})
}

func TestRunCmd_Execute_RejectsFlagLikeValuesBeforeRunE(t *testing.T) {
	resetRunCmd(t)

	// A missing value for --executable swallows --error-on-block as its value. If this
	// were mistakenly allowed through to RunE, "not-a-real-pm" would surface a distinct
	// "unsupported command" error instead, so its absence confirms RunE was never reached.
	runCmd.SetArgs([]string{"--executable", "--error-on-block", "--", "not-a-real-pm", "--version"})
	err := runCmd.Execute()
	if err == nil {
		t.Fatal("runCmd.Execute() = nil error, want error for --executable swallowing --error-on-block")
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Fatalf("runCmd.Execute() error = %q, want it to mention executable", err)
	}
	if strings.Contains(err.Error(), "unsupported command") {
		t.Fatal("runCmd.Execute() reached RunE despite failing flag validation")
	}
}

func TestRunCmd_AcceptsLegitimateFlagValues(t *testing.T) {
	t.Cleanup(func() {
		executable = ""
		for _, name := range []string{"executable", "error-on-block"} {
			runCmd.Flags().Lookup(name).Changed = false
		}
	})

	args := []string{"--executable=/usr/bin/npm", "--error-on-block", "--", "npm", "install"}
	if err := runCmd.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags(%v) returned unexpected error: %v", args, err)
	}
	if err := validateRunArgs(runCmd, runCmd.Flags().Args()); err != nil {
		t.Fatalf("validateRunArgs() returned unexpected error: %v", err)
	}
	if err := rejectFlagLikeValues(runCmd); err != nil {
		t.Fatalf("rejectFlagLikeValues() returned unexpected error: %v", err)
	}
	if executable != "/usr/bin/npm" {
		t.Fatalf("executable = %q, want %q", executable, "/usr/bin/npm")
	}
}

func TestFormatEvaluationDetails(t *testing.T) {
	tests := []struct {
		name        string
		report      ddapi.ScfwPolicyEvaluationReport
		wantContain []string
		wantOmit    []string
	}{
		{
			name:     "allow prints nothing",
			report:   ddapi.ScfwPolicyEvaluationReport{Outcome: ddapi.OutcomeAllow},
			wantOmit: []string{"ALLOW"},
		},
		{
			name: "block prints only the blocking package and its matched policy",
			report: ddapi.ScfwPolicyEvaluationReport{
				Outcome: ddapi.OutcomeBlock,
				Results: []ddapi.PackageEvaluationResult{
					{Ecosystem: "npm", PackageName: "left-pad", PackageVersion: "1.0.0", Outcome: ddapi.OutcomeAllow},
					{Ecosystem: "npm", PackageName: "evil-pkg", PackageVersion: "6.6.6", Outcome: ddapi.OutcomeBlock},
				},
			},
			wantContain: []string{"BLOCK", "evil-pkg@6.6.6"},
			wantOmit:    []string{"left-pad"},
		},
		{
			name:        "error outcome still prints",
			report:      ddapi.ScfwPolicyEvaluationReport{Outcome: ddapi.OutcomeError},
			wantContain: []string{"ERROR"},
		},
		{
			name:        "unexpected outcome still prints",
			report:      ddapi.ScfwPolicyEvaluationReport{Outcome: ddapi.Outcome("UNKNOWN")},
			wantContain: []string{"UNKNOWN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := formatEvaluationDetails(tt.report)

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("formatEvaluationDetails() output %q does not contain %q", output, want)
				}
			}
			for _, omit := range tt.wantOmit {
				if strings.Contains(output, omit) {
					t.Errorf("formatEvaluationDetails() output %q unexpectedly contains %q", output, omit)
				}
			}
		})
	}
}

func TestResolveWarningAction_UsesResolvedOnWarning(t *testing.T) {
	tests := []struct {
		onWarning     ddapi.Outcome
		isInteractive bool
		want          ddapi.Outcome
	}{
		{ddapi.OutcomeAllow, false, ddapi.OutcomeAllow},
		{ddapi.OutcomeBlock, false, ddapi.OutcomeBlock},
		{ddapi.OutcomeAllow, true, ddapi.OutcomeAllow},
		{ddapi.OutcomeBlock, true, ddapi.OutcomeBlock},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/isInteractive=%v", tt.onWarning, tt.isInteractive), func(t *testing.T) {
			onWarning = tt.onWarning
			t.Cleanup(func() { onWarning = ddapi.OutcomeWarn })

			if got := resolveWarningAction(tt.isInteractive); got != tt.want {
				t.Errorf("resolveWarningAction(%v) = %q, want %q", tt.isInteractive, got, tt.want)
			}
		})
	}
}
