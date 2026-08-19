// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import "testing"

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
