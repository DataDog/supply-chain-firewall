// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPipInterpreterLauncherFormats(t *testing.T) {
	directory := t.TempDir()
	python := filepath.Join(directory, "python3")
	writePipFixture(t, python, "")
	if err := os.Chmod(python, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, test := range []struct{ name, body, want string }{
		{"direct", fmt.Sprintf(readPipFixture(t, "config/launcher.tmpl"), python), python},
		{"env", fmt.Sprintf(readPipFixture(t, "config/launcher.tmpl"), "/usr/bin/env python3"), python},
		{"distlib", fmt.Sprintf(readPipFixture(t, "interpreter/distlib-launcher.tmpl"), "/venv with spaces/bin/python"), "/venv with spaces/bin/python"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pip")
			writePipFixture(t, path, test.body)
			got, err := interpreterFromLauncher(path)
			if err != nil || got != test.want {
				t.Fatalf("interpreter=%q error=%v, want %q", got, err, test.want)
			}
		})
	}
}

func TestPipShellShimResolvesAndCachesSelectedInterpreter(t *testing.T) {
	goDiscoveryPip(t)
	fixturePip(t)
	prefix := filepath.Join(t.TempDir(), "selected venv")
	python := filepath.Join(prefix, "bin", "python")
	writePipFixture(t, python, "")
	writePipFixture(t, filepath.Join(prefix, "pyvenv.cfg"), readPipFixture(t, "config/pyvenv.cfg"))
	writePipFixture(t, filepath.Join(prefix, "pip.conf"), readPipFixture(t, "config/target.conf"))
	t.Setenv("PIP_CONFIG_FILE", "")
	if err := os.Unsetenv("PIP_CONFIG_FILE"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCFW_TEST_PIP_PYTHON", python)
	t.Setenv("SCFW_TEST_PIP_EXECUTABLE", os.Args[0])
	marker := filepath.Join(t.TempDir(), "diagnostics")
	t.Setenv("SCFW_TEST_PIP_DEBUG_COUNT", marker)
	shim := filepath.Join(t.TempDir(), "pip")
	writePipFixture(t, shim, readPipFixture(t, "interpreter/shim.sh"))
	if err := os.Chmod(shim, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := interpreterFromLauncher(shim); err == nil {
		t.Fatal("fixture did not require diagnostic fallback")
	}
	manager, err := NewPip(context.Background(), "pip", shim)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 8 {
		copy := manager
		group.Add(1)
		go func() {
			defer group.Done()
			settings, err := copy.settings([]string{"download", "project"})
			if err != nil || settings.HTTPS != "http://target.example" {
				t.Errorf("selected venv settings=%+v error=%v", settings, err)
			}
		}()
	}
	group.Wait()
	if _, err := manager.ProxyOptions([]string{"download", "project"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PyPIClassifierOptions([]string{"download", "project"}); err != nil {
		t.Fatal(err)
	}
	if manager.Executable() != shim {
		t.Fatal("discovery replaced the selected shim executable")
	}
	calls, err := os.ReadFile(marker)
	if err != nil || string(calls) != "debug\n" {
		t.Fatalf("diagnostic calls=%q error=%v, want one", calls, err)
	}
	fresh, err := NewPip(context.Background(), "pip", shim)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.interpreter(); err != nil || got != python {
		t.Fatalf("fresh interpreter=%q error=%v", got, err)
	}
	calls, err = os.ReadFile(marker)
	if err != nil || string(calls) != "debug\ndebug\n" {
		t.Fatalf("cache leaked across adapters: %q %v", calls, err)
	}
}

func TestPipDiagnosticFailuresAreBoundedAndRedacted(t *testing.T) {
	fixturePip(t)
	t.Setenv("SCFW_TEST_PIP_PYTHON", filepath.Join(t.TempDir(), "python"))
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	for _, mode := range []string{"failure", "missing", "relative", "duplicate", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SCFW_TEST_PIP_DEBUG_MODE", mode)
			timeout := 5 * time.Second
			if mode == "timeout" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			path, err := interpreterFromDiagnostics(ctx, os.Args[0])
			if err == nil || path != "" {
				t.Fatalf("accepted invalid diagnostics: %q %v", path, err)
			}
			if mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout error=%v", err)
			}
			if strings.Contains(err.Error(), "diagnostic-secret") || strings.Contains(logs.String(), "diagnostic-secret") {
				t.Fatal("diagnostic output exposed credentials")
			}
		})
	}
}
