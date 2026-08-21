// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootHelpIdentifiesDatadogAndIncludesExamples(t *testing.T) {
	cmd := RootCmd()
	defer cmd.RemoveCommand(configureCmd, runCmd)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned unexpected error: %v", err)
	}

	for _, want := range []string{
		"Datadog",
		"Examples:",
		"scfw configure --dd-api-key=<your-api-key> --dd-app-key=<your-app-key> --alias-npm --alias-pip --alias-poetry",
		"scfw run -- npm install react",
		"scfw run -- pip install requests",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("help output %q does not contain %q", output.String(), want)
		}
	}
}

func TestConfigureLogging_VerboseEnvironmentEnablesDebug(t *testing.T) {
	t.Setenv(verboseEnvVar, "true")
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	if err := configureLogging("WARNING"); err != nil {
		t.Fatalf("configureLogging() returned unexpected error: %v", err)
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("SCFW_VERBOSE did not enable debug logging")
	}
}

func TestRejectFlagLikeValues(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("scfw-home", "", "")
		cmd.Flags().String("dd-site", "", "")
		cmd.Flags().Bool("alias-npm", false, "")
		return cmd
	}

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		wantFlag string
	}{
		{name: "no flags given", args: nil},
		{name: "normal value", args: []string{"--scfw-home", "/tmp/foo"}},
		{name: "equals form with normal value", args: []string{"--dd-site=datadoghq.com"}},
		{name: "bool flag alone is unaffected", args: []string{"--alias-npm"}},
		{name: "single dash value is allowed", args: []string{"--scfw-home", "-"}},
		{
			name:     "space-separated flag swallows the next flag as its value",
			args:     []string{"--scfw-home", "--alias-npm"},
			wantErr:  true,
			wantFlag: "scfw-home",
		},
		{
			name:     "equals form with a flag-like value is still rejected",
			args:     []string{"--dd-site=--alias-npm"},
			wantErr:  true,
			wantFlag: "dd-site",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCmd()
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags(%v) returned unexpected error: %v", tt.args, err)
			}

			err := rejectFlagLikeValues(cmd)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("rejectFlagLikeValues() = nil error, want error for args %v", tt.args)
				}
				if !strings.Contains(err.Error(), tt.wantFlag) {
					t.Errorf("rejectFlagLikeValues() error = %q, want it to mention %q", err, tt.wantFlag)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejectFlagLikeValues() returned unexpected error: %v", err)
			}
		})
	}
}
