//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHarnessPip3VersionPin(t *testing.T) {
	fixture, err := os.ReadFile("testdata/pip_baseline/launcher-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, proxy := range []string{"", "1"} {
		mode := "resolution"
		if proxy == "1" {
			mode = "proxy"
		}
		for _, test := range []struct {
			name, version, exit string
			accepted            bool
		}{
			{name: "matching", version: "26.2.2", accepted: true},
			{name: "mismatched", version: "25.1"},
			{name: "matching-prefix", version: "26.2.20"},
			{name: "failed-probe", version: "26.2.2", exit: "3"},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				root := t.TempDir()
				env, err := isolatedEnvironment(root)
				if err != nil {
					t.Fatal(err)
				}
				bin := filepath.Join(root, "bin")
				if err := os.MkdirAll(bin, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"pip", "pip3", "python", "git", "scfw"} {
					if err := os.WriteFile(filepath.Join(bin, name), fixture, 0700); err != nil {
						t.Fatal(err)
					}
				}
				env["SCFW_HARNESS_PIP3_VERSION"] = test.version
				env["SCFW_HARNESS_PIP3_EXIT"] = test.exit
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				r := &caseRun{Context: ctx, Root: root, WorkDir: filepath.Join(root, "work"), Env: env,
					Cell:   cell{Executable: filepath.Join(bin, "pip"), ManagerVersion: "26.2.2", Runtime: filepath.Join(bin, "python"), Git: filepath.Join(bin, "git")},
					Binary: filepath.Join(bin, "scfw"), Result: &result{}}
				// The selected pip matches the matrix even when its adjacent pip3 does not.
				pip, err := r.Command("selected-pip-version", r.Cell.Executable, "--version")
				if err != nil {
					t.Fatal(err)
				}
				output, err := os.ReadFile(pip.Stdout.Path)
				if err != nil || !strings.HasPrefix(string(output), "pip 26.2.2 ") {
					t.Fatalf("selected pip fixture: %q, %v", output, err)
				}
				err = runPipBaseline(r, pipOptions{launcher: "pip3", proxy: proxy})
				var failure caseFailure
				if test.accepted {
					// Exit 42 is the downstream command sentinel, after launcher validation.
					if err == nil || !strings.Contains(err.Error(), "SCFW exit=42") {
						t.Fatalf("matching launcher did not reach SCFW: %v", err)
					}
				} else if !errors.As(err, &failure) || failure.status != "INFRASTRUCTURE_FAILURE" {
					t.Fatalf("invalid pip3 must fail as infrastructure before SCFW: %v", err)
				}
				probed, executed := false, false
				for _, command := range r.Result.Commands {
					if len(command.Argv) == 2 && command.Argv[0] == filepath.Join(bin, "pip3") && command.Argv[1] == "--version" {
						probed = true
						if _, err := os.Stat(command.Stdout.Path); err != nil {
							t.Fatal("missing launcher version evidence:", err)
						}
					}
					executed = executed || command.Argv[0] == r.Binary
				}
				if !probed || executed != test.accepted {
					t.Fatalf("pip3 version probe=%v, protected command executed=%v; accepted=%v", probed, executed, test.accepted)
				}
			})
		}
	}
}
