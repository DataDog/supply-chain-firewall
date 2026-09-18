// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type npmScriptShell struct {
	directory   string
	path        string
	environment []string
}

type restoredEnvironmentValue struct {
	name       string
	backupName string
}

// newNPMScriptShell creates a wrapper that removes SCFW's process-local npm
// overrides and closes the authentication descriptor before lifecycle scripts.
func newNPMScriptShell(originalShell string, environment []string, overriddenNames []string) (*npmScriptShell, error) {
	if originalShell == "" {
		originalShell = "/bin/sh"
	}
	directory, err := os.MkdirTemp("", "scfw-npm-shell-")
	if err != nil {
		return nil, fmt.Errorf("create temporary npm script shell directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, errors.Join(fmt.Errorf("protect temporary npm script shell directory: %w", err), os.RemoveAll(directory))
	}

	originalValues := make(map[string]string)
	usedNames := make(map[string]bool)
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		if ok {
			originalValues[name] = value
			usedNames[name] = true
		}
	}
	sort.Strings(overriddenNames)
	wrapperEnvironment := append([]string(nil), environment...)
	restoredValues := make([]restoredEnvironmentValue, 0, len(overriddenNames))
	backupIndex := 0
	for _, name := range overriddenNames {
		value, ok := originalValues[name]
		if !ok {
			continue
		}
		var backupName string
		for {
			backupName = fmt.Sprintf("SCFW_NPM_ORIGINAL_%d", backupIndex)
			backupIndex++
			if !usedNames[backupName] {
				break
			}
		}
		usedNames[backupName] = true
		wrapperEnvironment = append(wrapperEnvironment, backupName+"="+value)
		restoredValues = append(restoredValues, restoredEnvironmentValue{name: name, backupName: backupName})
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\nexec 3<&- 3>&-\nexec env")
	for _, name := range overriddenNames {
		script.WriteString(" -u ")
		script.WriteString(shellQuote(name))
	}
	for _, restored := range restoredValues {
		script.WriteString(" -u ")
		script.WriteString(shellQuote(restored.backupName))
	}
	for _, restored := range restoredValues {
		script.WriteByte(' ')
		script.WriteString(shellQuote(restored.name + "="))
		script.WriteString("\"${")
		script.WriteString(restored.backupName)
		script.WriteString("}\"")
	}
	script.WriteByte(' ')
	script.WriteString(shellQuote(originalShell))
	script.WriteString(" \"$@\"\n")

	path := filepath.Join(directory, "script-shell")
	if err := os.WriteFile(path, []byte(script.String()), 0o700); err != nil {
		return nil, errors.Join(fmt.Errorf("write temporary npm script shell: %w", err), os.RemoveAll(directory))
	}
	return &npmScriptShell{directory: directory, path: path, environment: wrapperEnvironment}, nil
}

func (shell *npmScriptShell) Close() error {
	return os.RemoveAll(shell.directory)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
