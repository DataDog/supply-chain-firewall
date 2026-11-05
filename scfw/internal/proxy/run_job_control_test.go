// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestRunInteractiveJobControlHelper(t *testing.T) {
	if os.Getenv("SCFW_TEST_JOB_CONTROL") != "1" {
		t.Skip("PTY subprocess only")
	}
	directory := os.Getenv("SCFW_TEST_JOB_DIR")
	if err := os.WriteFile(filepath.Join(directory, "wrapper"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	commandErr, setupErr := Run(ctx, Options{}, []string{"install", "project"}, commandConfigurerFunc(func(context.Context, []string, ClientConfig) (CommandSpec, error) {
		return CommandSpec{Executable: filepath.Join(directory, "command")}, nil
	}))
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	err := commandErr
	if err != nil {
		if _, ok := errors.AsType[*exec.ExitError](err); !ok {
			t.Fatal(err)
		}
	}
}

func TestRunInteractiveJobControl(t *testing.T) {
	jobCommandFixture := readProxyFixture(t, "job-command.py")
	jobDriverFixture := readProxyFixture(t, "job-driver.py")
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash required for interactive job-control test")
	}
	directory := t.TempDir()
	t.Setenv("SCFW_TEST_JOB_CONTROL", "1")
	t.Setenv("SCFW_TEST_JOB_DIR", directory)
	script := "#!" + interpreter + "\n" + jobCommandFixture
	if err := os.WriteFile(filepath.Join(directory, "command"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	driver := jobDriverFixture
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, interpreter, "-c", driver, bash, os.Args[0])
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("interactive job control: %v\n%s", err, output)
	}
}
