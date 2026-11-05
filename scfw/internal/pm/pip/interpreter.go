// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (pip Pip) interpreter() (string, error) {
	if pip.resolveInterpreter != nil {
		return pip.resolveInterpreter()
	}
	return discoverPipInterpreter(pip.executable)
}

func discoverPipInterpreter(executable string) (string, error) {
	if interpreter, err := interpreterFromLauncher(executable); err == nil {
		return interpreter, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return interpreterFromDiagnostics(ctx, executable)
}

func interpreterFromLauncher(executable string) (string, error) {
	data, err := os.ReadFile(executable)
	if err != nil {
		return "", errors.New("could not read pip executable")
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if strings.HasPrefix(line, "#!") && len(fields) == 1 && strings.Contains(fields[0], "python") {
		return fields[0], nil
	}
	if len(fields) == 2 && fields[0] == "/usr/bin/env" && strings.HasPrefix(fields[1], "python") {
		return exec.LookPath(fields[1])
	}
	// distlib uses a shell trampoline when the interpreter path contains spaces
	// or exceeds the kernel's shebang limit.
	if strings.HasPrefix(string(data), "#!/bin/sh\n'''exec' ") {
		path, _, ok := strings.Cut(strings.TrimPrefix(string(data), "#!/bin/sh\n'''exec' "), " \"$0\"")
		if ok {
			return strings.Trim(path, "\""), nil
		}
	}
	return "", errors.New("cannot determine pip's Python interpreter from its launcher")
}

// Query the selected executable so shell shims retain their interpreter choice.
// Only the executable path is retained; diagnostic output can contain secrets.
func interpreterFromDiagnostics(ctx context.Context, executable string) (string, error) {
	command := exec.CommandContext(ctx, executable, "debug", "--disable-pip-version-check", "--no-input", "--no-color")
	command.WaitDelay = time.Second
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("could not determine pip's Python interpreter from diagnostics")
	}
	interpreter := ""
	for _, line := range strings.Split(string(output), "\n") {
		value, found := strings.CutPrefix(strings.TrimSpace(line), "sys.executable:")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		if interpreter != "" || !filepath.IsAbs(value) {
			return "", errors.New("pip diagnostics did not report one absolute Python interpreter")
		}
		interpreter = strings.Clone(value)
	}
	if interpreter == "" {
		return "", errors.New("pip diagnostics did not report a Python interpreter")
	}
	return interpreter, nil
}
