// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/spf13/cobra"
)

func TestDoctorCmdHasHandler(t *testing.T) {
	if doctorCmd.Name() != "doctor" {
		t.Fatalf("doctorCmd.Name() = %q, want doctor", doctorCmd.Name())
	}
	if doctorCmd.RunE == nil {
		t.Fatal("doctor command has no RunE handler")
	}
}

func TestDoctorCmdRejectsArguments(t *testing.T) {
	if err := doctorCmd.Args(doctorCmd, []string{"unexpected"}); err == nil {
		t.Fatal("doctor command accepted an unexpected positional argument")
	}
}

func TestDoctorCmd_DiagnosticFailuresDoNotPrintUsage(t *testing.T) {
	t.Setenv("DD_API_KEY", "api-key")
	t.Setenv("DD_APP_KEY", "app-key")
	t.Setenv("HOME", "")

	origSilenceUsage := doctorCmd.SilenceUsage
	t.Cleanup(func() { doctorCmd.SilenceUsage = origSilenceUsage })

	cmd := RootCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"doctor"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() = nil error, want shell-configuration diagnostic error")
	}
	if !strings.Contains(err.Error(), "could not locate shell configuration") {
		t.Fatalf("Execute() error = %q, want shell-configuration diagnostic", err)
	}
	if strings.Contains(output.String(), "Usage:") {
		t.Fatalf("Execute() output contains usage for a diagnostic failure: %q", output.String())
	}
}

func TestReportCredentialDistinguishesCredentialErrors(t *testing.T) {
	var output bytes.Buffer
	apiErr := errors.New("API key lookup failed")
	appErr := errors.New("application key lookup failed")

	if err := reportCredential(&output, "API Key", "", ddapi.CredentialSourceKeychain, apiErr); err != nil {
		t.Fatalf("reportCredential() returned unexpected error: %v", err)
	}
	if err := reportCredential(&output, "Application Key", "", ddapi.CredentialSourceKeychain, appErr); err != nil {
		t.Fatalf("reportCredential() returned unexpected error: %v", err)
	}

	wantLines := []string{
		"❌ API Key not found: API key lookup failed",
		"❌ Application Key not found: application key lookup failed",
	}
	for _, want := range wantLines {
		if !strings.Contains(output.String(), want+"\n") {
			t.Errorf("reportCredential() output = %q, want line %q", output.String(), want)
		}
	}
}

func TestReportAliases(t *testing.T) {
	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	zshrc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(bashrc, []byte(blockStart+"\n"+
		`alias npm="scfw run -- npm"`+"\n"+
		`alias pip="scfw run -- pip"`+"\n"+
		`alias pip3="scfw run -- pip3"`+"\n"+blockEnd+"\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", bashrc, err)
	}
	if err := os.WriteFile(zshrc, []byte(blockStart+"\n"+
		`alias npm="scfw run -- npm"`+"\n"+
		`alias poetry="scfw run -- poetry"`+"\n"+blockEnd+"\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", zshrc, err)
	}

	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := reportAliases(cmd, home); err != nil {
		t.Fatalf("reportAliases() returned unexpected error: %v", err)
	}

	wantLines := []string{
		"✅ Alias npm is set in " + bashrc + ", " + zshrc,
		"✅ Alias pip is set in " + bashrc,
		"✅ Alias pip3 is set in " + bashrc,
		"✅ Alias poetry is set in " + zshrc,
		"ℹ️ Run `alias npm pip pip3 poetry` to check which aliases are active in the current terminal. If an alias configured above is not found, reload your terminal.",
	}
	for _, want := range wantLines {
		if !strings.Contains(output.String(), want+"\n") {
			t.Errorf("reportAliases() output = %q, want line %q", output.String(), want)
		}
	}
}

func TestReportAliases_RejectsAliasThatBypassesScfw(t *testing.T) {
	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte(blockStart+"\n"+
		`alias npm=npm`+"\n"+blockEnd+"\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", bashrc, err)
	}

	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := reportAliases(cmd, home); err == nil {
		t.Fatal("reportAliases() = nil error, want invalid-target error")
	}

	want := `❌ Alias npm in ` + bashrc + ` targets "npm"; expected "scfw run -- npm"`
	if !strings.Contains(output.String(), want+"\n") {
		t.Errorf("reportAliases() output = %q, want line %q", output.String(), want)
	}
	if strings.Contains(output.String(), "✅ Alias npm") {
		t.Errorf("reportAliases() marked bypassing npm alias healthy: %q", output.String())
	}
}

func TestReportAliases_ReturnsErrorForMissingAlias(t *testing.T) {
	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte(blockStart+"\n"+
		`alias npm="scfw run -- npm"`+"\n"+
		`alias pip="scfw run -- pip"`+"\n"+
		`alias pip3="scfw run -- pip3"`+"\n"+blockEnd+"\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", bashrc, err)
	}

	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	err := reportAliases(cmd, home)
	if err == nil {
		t.Fatal("reportAliases() = nil error, want missing-alias error")
	}
	if !strings.Contains(err.Error(), "alias poetry is not set") {
		t.Fatalf("reportAliases() error = %v, want missing poetry alias", err)
	}
	if !strings.Contains(output.String(), "❌ Alias poetry is not set\n") {
		t.Errorf("reportAliases() output = %q, want missing poetry diagnostic", output.String())
	}
}

func TestReportAliases_ReportsUnreadableConfigAndContinues(t *testing.T) {
	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte(blockStart+"\nalias npm=command\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", bashrc, err)
	}

	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := reportAliases(cmd, home); err == nil {
		t.Fatal("reportAliases() = nil error, want malformed-block error")
	}
	if !strings.Contains(output.String(), "Could not read aliases from "+bashrc) {
		t.Fatalf("reportAliases() output = %q, want read warning for %q", output.String(), bashrc)
	}
	for _, name := range availableAliases {
		if !strings.Contains(output.String(), "Alias "+name+" is not set") {
			t.Errorf("reportAliases() output = %q, want missing status for %q", output.String(), name)
		}
	}
}
