// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type commandConfigurerFunc func(context.Context, []string, ClientConfig) (CommandSpec, error)

func (configure commandConfigurerFunc) ProxyCommand(ctx context.Context, command []string, config ClientConfig) (CommandSpec, error) {
	return configure(ctx, command, config)
}

func TestRunCommandHelper(t *testing.T) {
	switch os.Getenv("SCFW_TEST_PROXY_COMMAND") {
	case "":
		t.Skip("subprocess only")
	case "exit":
		os.Exit(17)
	case "environment":
		values := map[string]any{"keep": os.Getenv("SCFW_RUN_KEEP"), "replace": os.Getenv("SCFW_RUN_REPLACE"), "empty": os.Getenv("SCFW_RUN_EMPTY"), "args": os.Args[len(os.Args)-2:]}
		data, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("SCFW_RUN_RESULT"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunAppliesOnlyChildEnvironmentAndPreservesArguments(t *testing.T) {
	t.Setenv("SCFW_RUN_KEEP", "parent-keep")
	t.Setenv("SCFW_RUN_REPLACE", "parent-replace")
	t.Setenv("SCFW_RUN_EMPTY", "parent-empty")
	result := filepath.Join(t.TempDir(), "result.json")
	command := []string{"argument with spaces", "--literal=value"}
	var seen ClientConfig
	configure := commandConfigurerFunc(func(_ context.Context, args []string, config ClientConfig) (CommandSpec, error) {
		seen = config
		if _, err := os.Stat(config.CACertificatePath); err != nil {
			t.Fatal(err)
		}
		return CommandSpec{Executable: os.Args[0], Args: append([]string{"-test.run=^TestRunCommandHelper$", "--"}, args...), EnvOverrides: map[string]string{"SCFW_TEST_PROXY_COMMAND": "environment", "SCFW_RUN_RESULT": result, "SCFW_RUN_REPLACE": "child", "SCFW_RUN_EMPTY": ""}}, nil
	})
	commandErr, setupErr := Run(context.Background(), Options{}, command, configure)
	if commandErr != nil || setupErr != nil {
		t.Fatalf("run: %v / %v", commandErr, setupErr)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Keep, Replace, Empty string
		Args                 []string
	}
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	if values.Keep != "parent-keep" || values.Replace != "child" || values.Empty != "" || !slices.Equal(values.Args, command) {
		t.Fatalf("child values: %+v", values)
	}
	if os.Getenv("SCFW_RUN_REPLACE") != "parent-replace" || os.Getenv("SCFW_RUN_EMPTY") != "parent-empty" {
		t.Fatal("parent environment changed")
	}
	assertRunProxyStopped(t, seen)
}

func TestRunPreservesProcessExitCode(t *testing.T) {
	var seen ClientConfig
	configure := commandConfigurerFunc(func(_ context.Context, _ []string, config ClientConfig) (CommandSpec, error) {
		seen = config
		return CommandSpec{Executable: os.Args[0], Args: []string{"-test.run=^TestRunCommandHelper$"}, EnvOverrides: map[string]string{"SCFW_TEST_PROXY_COMMAND": "exit"}}, nil
	})
	commandErr, setupErr := Run(context.Background(), Options{}, nil, configure)
	exit, ok := errors.AsType[*exec.ExitError](commandErr)
	if setupErr != nil || !ok || exit.ExitCode() != 17 {
		t.Fatalf("run: %v / %v; want exit 17", commandErr, setupErr)
	}
	assertRunProxyStopped(t, seen)
}

func TestRunCleansUpOnPreparationFailureAndPanic(t *testing.T) {
	failure := errors.New("configuration failed")
	for _, test := range []struct {
		name                  string
		cancel, panics, empty bool
	}{{name: "failure"}, {name: "cancellation", cancel: true}, {name: "panic", panics: true}, {name: "empty executable", empty: true}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var seen ClientConfig
			var setupErr, commandErr error
			configure := commandConfigurerFunc(func(_ context.Context, _ []string, config ClientConfig) (CommandSpec, error) {
				seen = config
				if test.panics {
					panic("adapter bug")
				}
				if test.cancel {
					cancel()
					return CommandSpec{}, ctx.Err()
				}
				if test.empty {
					return CommandSpec{}, nil
				}
				return CommandSpec{}, failure
			})
			panicked := func() (panicked bool) {
				defer func() { panicked = recover() != nil }()
				commandErr, setupErr = Run(ctx, Options{}, nil, configure)
				return false
			}()
			if panicked != test.panics {
				t.Fatalf("panic=%v, want %v", panicked, test.panics)
			}
			if !test.panics {
				if commandErr != nil || setupErr == nil {
					t.Fatalf("run: %v / %v", commandErr, setupErr)
				}
				if test.cancel && !errors.Is(setupErr, context.Canceled) {
					t.Fatal(setupErr)
				}
				if !test.cancel && !test.empty && !errors.Is(setupErr, failure) {
					t.Fatal(setupErr)
				}
			}
			assertRunProxyStopped(t, seen)
		})
	}
}

func TestApplyEnvironmentOverridesReplacesDuplicates(t *testing.T) {
	original := []string{"KEEP=value", "REPLACE=first", "REPLACE=second", "EMPTY=old"}
	before := slices.Clone(original)
	got := applyEnvironmentOverrides(original, map[string]string{"REPLACE": "new", "EMPTY": "", "ADD": "added"})
	want := []string{"KEEP=value", "ADD=added", "EMPTY=", "REPLACE=new"}
	if !slices.Equal(got, want) || !slices.Equal(original, before) {
		t.Fatalf("environment=%q original=%q", got, original)
	}
}

func assertRunProxyStopped(t *testing.T, config ClientConfig) {
	t.Helper()
	if _, err := os.Stat(filepath.Dir(config.CACertificatePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proxy CA directory remains: %v", err)
	}
	// The core's listener is loopback-only, so a direct dial also proves it closed.
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(config.URL, "http://"), time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatal("proxy still listening")
	}
}
func TestRunCancellationForwardsSignalToBuildChildren(t *testing.T) {
	signalCommandFixture := readProxyFixture(t, "signal-command.py")
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required")
	}
	directory := t.TempDir()
	t.Setenv("SCFW_TEST_SIGNAL_DIR", directory)
	launcher := filepath.Join(directory, "command")
	script := "#!" + interpreter + "\n" + signalCommandFixture
	if err := os.WriteFile(launcher, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() {
		commandErr, setupErr := Run(ctx, Options{}, []string{"install", "example"}, commandConfigurerFunc(func(context.Context, []string, ClientConfig) (CommandSpec, error) {
			return CommandSpec{Executable: launcher}, nil
		}))
		if setupErr != nil {
			result <- setupErr
		} else {
			result <- commandErr
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(directory, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("test command did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		exit, ok := errors.AsType[*exec.ExitError](err)
		if !ok || exit.ExitCode() != 42 {
			t.Fatalf("command exit lost: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("command/process group did not exit")
	}
	for _, name := range []string{"parent-signal", "child-signal"} {
		value, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || string(value) != strconv.Itoa(int(syscall.SIGTERM)) {
			t.Fatalf("%s: got %s, %v", name, value, err)
		}
	}
}

func TestRunSIGTERMCancelsPreparation(t *testing.T) {
	var seen ClientConfig
	configure := commandConfigurerFunc(func(ctx context.Context, _ []string, config ClientConfig) (CommandSpec, error) {
		seen = config
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			return CommandSpec{}, err
		}
		select {
		case <-ctx.Done():
			return CommandSpec{}, ctx.Err()
		case <-time.After(5 * time.Second):
			return CommandSpec{}, errors.New("SIGTERM did not cancel preparation")
		}
	})
	commandErr, setupErr := Run(context.Background(), Options{}, nil, configure)
	if commandErr != nil || !errors.Is(setupErr, context.Canceled) {
		t.Fatalf("run: %v / %v", commandErr, setupErr)
	}
	assertRunProxyStopped(t, seen)
}
