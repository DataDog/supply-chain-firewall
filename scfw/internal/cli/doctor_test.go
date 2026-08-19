// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestReportAliases(t *testing.T) {
	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	zshrc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(bashrc, []byte(blockStart+"\n"+
		`alias npm="scfw run -- npm"`+"\n"+
		`alias pip="scfw run -- pip"`+"\n"+blockEnd+"\n"), 0o644); err != nil {
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
		"❌ Alias pip3 is not set",
		"✅ Alias poetry is set in " + zshrc,
	}
	for _, want := range wantLines {
		if !strings.Contains(output.String(), want+"\n") {
			t.Errorf("reportAliases() output = %q, want line %q", output.String(), want)
		}
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
