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
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHarnessPipLifecycleSummary(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/pip_baseline/lifecycle.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range suites["pip-baseline"] {
		if spec.Scenario != "LIFE-01" {
			continue
		}
		for _, failSubsequent := range []bool{false, true} {
			name := spec.Variant + "/subsequent-passes"
			if failSubsequent {
				name = spec.Variant + "/subsequent-fails"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				env, err := isolatedEnvironment(root)
				if err != nil {
					t.Fatal(err)
				}
				bin := filepath.Join(root, "bin")
				if err := os.MkdirAll(bin, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"python", "git", "scfw"} {
					if err := os.WriteFile(filepath.Join(bin, name), append([]byte("#!"+python+"\n"), fixture...), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if failSubsequent {
					if err := os.WriteFile(filepath.Join(bin, "fail-subsequent"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				r := &caseRun{Context: ctx, Spec: spec, Root: root, WorkDir: filepath.Join(root, "work"), Env: env,
					Cell:      cell{Executable: filepath.Join(bin, "pip"), Runtime: filepath.Join(bin, "python"), Git: filepath.Join(bin, "git")},
					Candidate: candidate{Ecosystem: "PyPI", Project: "fixture", Version: "1.0", Artifacts: []artifact{{URL: "https://example.invalid/fixture.whl", SHA256: strings.Repeat("a", 64)}}},
					Binary:    filepath.Join(bin, "scfw"), Result: &result{Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}}
				err = spec.Run(r)
				if (err != nil) != failSubsequent {
					t.Fatalf("subsequent failure=%v, got %v", failSubsequent, err)
				}
				if failSubsequent && !strings.Contains(err.Error(), "exit status 23") {
					t.Fatalf("unexpected failure: %v", err)
				}
				path := filepath.Join(root, "result.json")
				if err := writeJSON(path, r.Result); err != nil {
					t.Fatal(err)
				}
				var got result
				if err := readJSON(path, &got); err != nil {
					t.Fatal(err)
				}
				wantOutcome, wantExit := "ALLOW", 0
				if spec.Variant == "proxy-blocked-cleanup" {
					wantOutcome, wantExit = "BLOCK", 1
				}
				if got.PolicyOutcome != wantOutcome || got.ResolvedAction != wantOutcome || got.SCFWExit != wantExit || got.SCFWSignal != "" {
					t.Fatalf("primary summary overwritten: policy=%s action=%s exit=%d signal=%q", got.PolicyOutcome, got.ResolvedAction, got.SCFWExit, got.SCFWSignal)
				}
				var exits []int
				for _, command := range got.Commands {
					if command.Argv[0] == r.Binary {
						exits = append(exits, command.ExitCode)
					}
					for _, evidence := range []fileEvidence{command.Stdout, command.Stderr} {
						actual, err := digestFile(evidence.Path)
						if err != nil || actual != evidence {
							t.Fatalf("missing command evidence: %+v, %v", evidence, err)
						}
					}
				}
				if !reflect.DeepEqual(exits, []int{wantExit, 0}) {
					t.Fatalf("lost primary or subsequent command: %v", exits)
				}
				for _, run := range []string{filepath.Base(root), "subsequent"} {
					policy, err := readPolicy(got.Evidence["policy-"+run].Path)
					want := wantOutcome
					if run == "subsequent" {
						want = "ALLOW"
					}
					if err != nil || len(policy) != 1 || policy[0].Outcome != want {
						t.Fatalf("lost %s policy evidence: %+v, %v", run, policy, err)
					}
					if run == "subsequent" && failSubsequent {
						continue
					}
					if _, ok := got.Observations["installed-"+run]; !ok {
						t.Fatalf("lost %s installed-state observation", run)
					}
					if _, ok := got.Evidence["cleanup-"+run]; !ok {
						t.Fatalf("lost %s cleanup evidence", run)
					}
				}
			})
		}
	}
}

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
