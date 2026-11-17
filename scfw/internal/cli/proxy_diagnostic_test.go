// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func diagnosticDocuments(t *testing.T, path string) ([]byte, []map[string]any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var result []map[string]any
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, record)
	}
	if len(result) < 2 || result[0]["type"] != "manifest" || result[len(result)-1]["type"] != "summary" {
		t.Fatalf("incomplete journal: %s", body)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("capture permissions: %v", info.Mode())
	}
	return body, result
}

// enableProxyDiagnosticAssertions adds capture validation to the existing real
// manager matrix without repeating installations or weakening its assertions.
func enableProxyDiagnosticAssertions(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SCFW_HOME", root)
	t.Setenv("SCFW_DEBUG", "1")
	t.Setenv("SCFW_DEBUG_OUTPUT", "")
	t.Cleanup(func() {
		if t.Failed() || t.Skipped() {
			return
		}
		files, err := filepath.Glob(filepath.Join(root, "diagnostics", "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatal("real-manager matrix produced no diagnostic capture")
		}
		var metadata bool
		for _, file := range files {
			body, records := diagnosticDocuments(t, file)
			if bytes.Contains(body, []byte("private:secret@")) {
				t.Fatal("registry credentials leaked into capture")
			}
			for _, record := range records {
				if record["type"] == "http.body" {
					data, _ := record["data"].(map[string]any)
					sample, _ := data["body"].(map[string]any)
					if sample["kind"] == "metadata" {
						metadata = true
					}
				}
			}
		}
		if !metadata {
			t.Fatal("no readable metadata response bodies captured by real-manager matrix")
		}
	})
}

type diagnosticProcessManager struct {
	fakeProxyPackageManager
	behavior string
}

func (m *diagnosticProcessManager) ProxyCommand(_ context.Context, _ []string, _ proxy.ClientConfig) (proxy.CommandSpec, error) {
	if m.behavior == "setup-failure" {
		return proxy.CommandSpec{}, errors.New("fixture setup failure")
	}
	return proxy.CommandSpec{Executable: os.Args[0], Args: []string{"-test.run=^TestDiagnosticProcessHelper$"}, EnvOverrides: map[string]string{"SCFW_DIAGNOSTIC_HELPER": "child"}}, nil
}
func (m *diagnosticProcessManager) ProxyCommandSupported([]string) bool {
	return m.behavior != "bypass"
}
func (*diagnosticProcessManager) RunCommand(context.Context, []string) error {
	fmt.Fprintln(os.Stdout, "DIRECT_EXECUTION_CANARY")
	return nil
}

// TestDiagnosticProcessHelper exercises the real os.Exit boundary in a fresh
// CLI process. It never substitutes the filesystem or finalization implementation.
func TestDiagnosticProcessHelper(t *testing.T) {
	switch os.Getenv("SCFW_DIAGNOSTIC_HELPER") {
	case "":
		return
	case "child":
		if path := os.Getenv("SCFW_DIAGNOSTIC_CHILD_READY"); path != "" {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				os.Exit(24)
			}
		}
		fmt.Fprintln(os.Stdout, "CHILD_TERMINAL_CANARY")
		switch os.Getenv("SCFW_DIAGNOSTIC_BEHAVIOR") {
		case "exit":
			os.Exit(17)
		case "signal", "interrupt":
			for {
				time.Sleep(time.Second)
			}
		default:
			os.Exit(0)
		}
	case "firewall":
		manager := &diagnosticProcessManager{behavior: os.Getenv("SCFW_DIAGNOSTIC_BEHAVIOR")}
		packageManagerFactories = []PackageManagerFactory{{Names: []string{"diagnostic-fixture"}, New: func(context.Context, string, string) (pm.PackageManager, error) { return manager, nil }}}
		command := RootCmd()
		command.SetArgs([]string{"run", "--", "diagnostic-fixture", "install", "--password", "command-password-canary"})
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := command.ExecuteContext(ctx); err != nil {
			os.Exit(23)
		}
		os.Exit(0)
	default:
		t.Fatal("unknown diagnostic fixture mode")
	}
}

func TestDiagnosticProcessExitAndFailures(t *testing.T) {
	for _, behavior := range []string{"success", "exit", "setup-failure", "signal", "interrupt", "bypass", "disabled", "collision"} {
		t.Run(behavior, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run.yaml")
			if behavior == "collision" {
				if err := os.WriteFile(path, []byte("EXISTING_FILE"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiagnosticProcessHelper$")
			ready := filepath.Join(filepath.Dir(path), "child-ready")
			command.Env = append(os.Environ(), "SCFW_DIAGNOSTIC_HELPER=firewall", "SCFW_DIAGNOSTIC_BEHAVIOR="+behavior, "SCFW_DIAGNOSTIC_CHILD_READY="+ready, "SCFW_MODE=local", "SCFW_PROXY_ENABLED=1", "SCFW_DEBUG=1", "SCFW_DEBUG_OUTPUT="+path, "SCFW_HOME="+t.TempDir())
			if behavior == "disabled" {
				command.Env = append(command.Env, "SCFW_DEBUG=0")
			}
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			if behavior == "signal" || behavior == "interrupt" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					_, readyErr := os.Stat(ready)
					started := readyErr == nil
					if started {
						break
					}
					if time.Now().After(deadline) {
						_ = command.Process.Kill()
						_ = command.Wait()
						t.Fatalf("child did not start: %s", output.String())
					}
					time.Sleep(10 * time.Millisecond)
				}
				sig := os.Signal(syscall.SIGTERM)
				if behavior == "interrupt" {
					sig = os.Interrupt
				}
				if err := command.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
			}
			err := command.Wait()
			want := 0
			switch behavior {
			case "exit":
				want = 17
			case "setup-failure":
				want = 23
			case "signal":
				want = 143
			case "interrupt":
				want = 130
			}
			if code := command.ProcessState.ExitCode(); code != want {
				t.Fatalf("exit=%d want=%d error=%v output=%s", code, want, err, &output)
			}
			if behavior == "bypass" || behavior == "disabled" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("captured a disabled/direct invocation")
				}
				if behavior == "bypass" && !strings.Contains(output.String(), "capture skipped") {
					t.Fatal("missing direct-execution warning")
				}
				return
			}
			if behavior == "collision" {
				body, _ := os.ReadFile(path)
				if string(body) != "EXISTING_FILE" {
					t.Fatal("overwrote existing output")
				}
				return
			}
			body, records := diagnosticDocuments(t, path)
			for _, forbidden := range []string{"CHILD_TERMINAL_CANARY", "command-password-canary"} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Fatalf("captured forbidden data: %s", forbidden)
				}
			}
			if behavior != "setup-failure" {
				var stopped bool
				for _, record := range records {
					stopped = stopped || record["type"] == "proxy.stop"
				}
				if !stopped {
					t.Fatal("finalized before proxy cleanup")
				}
			}
		})
	}
}
