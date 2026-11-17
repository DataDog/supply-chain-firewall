// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// DiagnosticInfo probes only for opt-in capture. Normal uv execution has no
// version subprocess. A failed or verbose launcher cannot prevent the command.
func (uv UV) DiagnosticInfo(ctx context.Context, _ []string) pm.DiagnosticInfo {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var output diagnosticVersionOutput
	command := exec.CommandContext(ctx, uv.executable, "--version")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 100 * time.Millisecond
	command.Stdout, command.Stderr = &output, io.Discard
	err := command.Run()
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if err != nil {
		return pm.DiagnosticInfo{Version: "unknown"}
	}
	fields := strings.Fields(output.String())
	if len(fields) < 2 {
		return pm.DiagnosticInfo{Version: "unknown"}
	}
	return pm.DiagnosticInfo{Version: fields[1]}
}

type diagnosticVersionOutput struct{ bytes.Buffer }

func (b *diagnosticVersionOutput) Write(data []byte) (int, error) {
	count := len(data)
	if b.Len() < 4096 {
		_, _ = b.Buffer.Write(data[:min(count, 4096-b.Len())])
	}
	return count, nil
}
