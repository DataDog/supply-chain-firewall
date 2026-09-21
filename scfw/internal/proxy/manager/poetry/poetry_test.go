// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistriesReadsProjectSourcesAndRequiresCurrentLock(t *testing.T) {
	directory := t.TempDir()
	project := `[tool.poetry]
name = "example"
version = "0.0.0"
[[tool.poetry.source]]
name = "private"
url = "https://packages.example/simple"
priority = "supplemental"
`
	if err := os.WriteFile(filepath.Join(directory, "pyproject.toml"), []byte(project), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "poetry.lock"), []byte("lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(directory, "poetry")
	if err := os.WriteFile(launcher, []byte("#!/usr/bin/python3\nraise SystemExit(0)\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	configuration, err := (&Manager{}).Registries(context.Background(), launcher, []string{"install", "--directory", directory})
	if err != nil {
		t.Fatalf("Registries() error = %v", err)
	}
	if got := configuration.Named["private"].String(); got != "https://packages.example/simple/" {
		t.Errorf("private source = %q", got)
	}
}
