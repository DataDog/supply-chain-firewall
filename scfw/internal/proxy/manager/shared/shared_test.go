// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package shared

import "testing"

func TestParseNPMJSON(t *testing.T) {
	registry, named, err := ParseNPMJSON([]byte(`{
		"registry":"https://ignored.example/npm",
		"registries":{"default":"https://registry.example/npm","structured":"https://structured.example"},
		"@private:registry":"https://private.example/packages"
	}`))
	if err != nil {
		t.Fatalf("ParseNPMJSON() error = %v", err)
	}
	if got, want := registry.String(), "https://registry.example/npm/"; got != want {
		t.Errorf("default registry = %q, want %q", got, want)
	}
	if got, want := named["@private"].String(), "https://private.example/packages/"; got != want {
		t.Errorf("scoped registry = %q, want %q", got, want)
	}
	if got, want := named["@structured"].String(), "https://structured.example/"; got != want {
		t.Errorf("structured registry = %q, want %q", got, want)
	}
}

func TestInsertOptionsBeforeSeparator(t *testing.T) {
	got := InsertOptions([]string{"install", "pkg", "--", "script-arg"}, []string{"--registry=proxy"})
	want := []string{"install", "pkg", "--registry=proxy", "--", "script-arg"}
	if len(got) != len(want) {
		t.Fatalf("InsertOptions() = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("InsertOptions() = %v, want %v", got, want)
		}
	}
}

func TestOperationSkipsGlobalOptions(t *testing.T) {
	optionsWithValue := map[string]bool{"--cwd": true}
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"install"}, want: "install"},
		{args: []string{"--silent", "INSTALL"}, want: "install"},
		{args: []string{"--cwd", "project", "install"}, want: "install"},
		{args: []string{"--cwd=project", "install"}, want: "install"},
		{args: []string{"--", "install"}, want: "install"},
		{args: []string{"--silent"}, want: ""},
	}
	for _, test := range tests {
		if got := Operation(test.args, optionsWithValue); got != test.want {
			t.Errorf("Operation(%v) = %q, want %q", test.args, got, test.want)
		}
	}
}
