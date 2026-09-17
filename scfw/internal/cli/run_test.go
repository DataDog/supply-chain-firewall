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

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/poetry"
)

func TestDiscoverGitMetadataUsesPackageManagerProjectDirectory(t *testing.T) {
	callerRepositoryDir := t.TempDir()
	projectRepositoryDir := t.TempDir()

	for directory, originURL := range map[string]string{
		callerRepositoryDir:  "https://example.com/acme/caller.git",
		projectRepositoryDir: "https://example.com/acme/project.git",
	} {
		repository, err := gogit.PlainInit(directory, false)
		if err != nil {
			t.Fatalf("PlainInit(%q) returned unexpected error: %v", directory, err)
		}
		_, err = repository.CreateRemote(&gitconfig.RemoteConfig{
			Name: gogit.DefaultRemoteName,
			URLs: []string{originURL},
		})
		if err != nil {
			t.Fatalf("CreateRemote(%q) returned unexpected error: %v", originURL, err)
		}
	}

	t.Chdir(callerRepositoryDir)
	metadata := discoverGitMetadata(poetry.Poetry{}, []string{"install", "--directory", projectRepositoryDir})
	if want := "https://example.com/acme/project.git"; metadata.RepositoryURL != want {
		t.Fatalf("discoverGitMetadata().RepositoryURL = %q, want %q", metadata.RepositoryURL, want)
	}
}

func TestDecideFirewallAction(t *testing.T) {
	tests := []struct {
		outcome evaluation.Outcome
		want    evaluation.Outcome
	}{
		{evaluation.OutcomeAllow, evaluation.OutcomeAllow},
		{evaluation.OutcomeBlock, evaluation.OutcomeBlock},
		{evaluation.OutcomeWarn, evaluation.OutcomeBlock},
		{evaluation.OutcomeError, evaluation.OutcomeBlock},
		{evaluation.Outcome("UNKNOWN"), evaluation.OutcomeBlock},
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
		wantOnWarning  evaluation.Outcome
		wantErr        bool
	}{
		{name: "no flags no env", wantOnWarning: evaluation.OutcomeWarn},
		{name: "allow flag", allowOnWarning: true, wantOnWarning: evaluation.OutcomeAllow},
		{name: "block flag", blockOnWarning: true, wantOnWarning: evaluation.OutcomeBlock},
		{name: "env allow overrides block flag", blockOnWarning: true, env: "allow", wantOnWarning: evaluation.OutcomeAllow},
		{name: "env block overrides allow flag", allowOnWarning: true, env: "block", wantOnWarning: evaluation.OutcomeBlock},
		{name: "env value is case-insensitive", env: "ALLOW", wantOnWarning: evaluation.OutcomeAllow},
		{name: "invalid env value", env: "nonsense", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowOnWarning = tt.allowOnWarning
			blockOnWarning = tt.blockOnWarning
			onWarning = evaluation.OutcomeWarn
			if tt.env != "" {
				os.Setenv(onWarningVar, tt.env)
			} else {
				os.Unsetenv(onWarningVar)
			}
			t.Cleanup(func() {
				allowOnWarning = false
				blockOnWarning = false
				onWarning = evaluation.OutcomeWarn
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
		want  evaluation.Outcome
	}{
		{name: "y", input: "y\n", want: evaluation.OutcomeAllow},
		{name: "yes", input: "yes\n", want: evaluation.OutcomeAllow},
		{name: "uppercase Y", input: "Y\n", want: evaluation.OutcomeAllow},
		{name: "mixed case Yes", input: "Yes\n", want: evaluation.OutcomeAllow},
		{name: "trims surrounding whitespace", input: "  yes  \n", want: evaluation.OutcomeAllow},
		{name: "n", input: "n\n", want: evaluation.OutcomeBlock},
		{name: "empty line", input: "\n", want: evaluation.OutcomeBlock},
		{name: "garbage", input: "sure\n", want: evaluation.OutcomeBlock},
		{name: "no trailing newline (read error)", input: "yes", want: evaluation.OutcomeBlock},
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
		report      evaluation.ScfwPolicyEvaluationReport
		wantContain []string
		wantOmit    []string
	}{
		{
			name:     "allow prints nothing",
			report:   evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow},
			wantOmit: []string{"ALLOW"},
		},
		{
			name: "block prints only the blocking package and its matched policy",
			report: evaluation.ScfwPolicyEvaluationReport{
				Outcome: evaluation.OutcomeBlock,
				Results: []evaluation.PackageEvaluationResult{
					{Ecosystem: "npm", PackageName: "left-pad", PackageVersion: "1.0.0", Outcome: evaluation.OutcomeAllow},
					{Ecosystem: "npm", PackageName: "evil-pkg", PackageVersion: "6.6.6", Outcome: evaluation.OutcomeBlock},
				},
			},
			wantContain: []string{"BLOCK", "evil-pkg@6.6.6"},
			wantOmit:    []string{"left-pad"},
		},
		{
			name:        "error outcome still prints",
			report:      evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeError},
			wantContain: []string{"ERROR"},
		},
		{
			name:        "unexpected outcome still prints",
			report:      evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.Outcome("UNKNOWN")},
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
		onWarning     evaluation.Outcome
		isInteractive bool
		want          evaluation.Outcome
	}{
		{evaluation.OutcomeAllow, false, evaluation.OutcomeAllow},
		{evaluation.OutcomeBlock, false, evaluation.OutcomeBlock},
		{evaluation.OutcomeAllow, true, evaluation.OutcomeAllow},
		{evaluation.OutcomeBlock, true, evaluation.OutcomeBlock},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/isInteractive=%v", tt.onWarning, tt.isInteractive), func(t *testing.T) {
			onWarning = tt.onWarning
			t.Cleanup(func() { onWarning = evaluation.OutcomeWarn })

			if got := resolveWarningAction(tt.isInteractive); got != tt.want {
				t.Errorf("resolveWarningAction(%v) = %q, want %q", tt.isInteractive, got, tt.want)
			}
		})
	}
}
