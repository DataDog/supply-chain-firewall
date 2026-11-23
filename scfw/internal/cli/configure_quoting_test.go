// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureExportsAreLiteral(t *testing.T) {
	for _, value := range []string{
		"ordinary path with spaces", `single ' and double " quotes`,
		`$HOME $(printf expanded) ` + "`printf expanded`",
		"backslash\\quote' trailing\\", "line\nbreak\tand\rreturn", "unicode é 世界", "control\a\b\v\f",
	} {
		t.Run(value, func(t *testing.T) {
			withScfwHome(t, value)
			withDdSite(t, value)
			block := buildManagedBlock(managedConfiguration{}, true, true)
			path := filepath.Join(t.TempDir(), "startup.sh")
			if err := os.WriteFile(path, []byte(blockStart+"\n"+block+blockEnd+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			config, err := readManagedConfiguration(path)
			if err != nil {
				t.Fatal(err)
			}
			if config.scfwHome != value || config.ddSite != value {
				t.Fatalf("configured values did not round-trip: %#v", config)
			}
			if got := buildManagedBlock(config, false, false); got != block {
				t.Fatalf("second configuration changed exports: %q -> %q", block, got)
			}
			for _, shell := range []string{"bash", "zsh"} {
				t.Run(shell, func(t *testing.T) {
					executable, err := exec.LookPath(shell)
					if err != nil {
						t.Skipf("%s unavailable", shell)
					}
					script, err := filepath.Abs("testdata/configure/exports.sh")
					if err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(executable, script, path)
					cmd.Env = append(os.Environ(), "SCFW_HOME=original", "DD_SITE=original")
					output, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("source generated exports: %v: %s", err, output)
					}
					if !bytes.Equal(output, []byte(value+"\x00"+value+"\x00")) {
						t.Fatalf("shell changed configured values: %q", output)
					}
				})
			}
		})
	}
}

func TestConfigureLegacyExportsRemainReadable(t *testing.T) {
	const value = `backslash\$HOME and "quote"`
	withScfwHome(t, "")
	withDdSite(t, "")
	path := filepath.Join(t.TempDir(), "startup.sh")
	// The old writer used Go double-quoted literals. Preserve their stored data
	// when an additive configuration migrates the block to safe shell quoting.
	legacy := blockStart + "\nexport SCFW_HOME=\"backslash\\\\$HOME and \\\"quote\\\"\"\n" + blockEnd + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readManagedConfiguration(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.scfwHome != value {
		t.Fatalf("legacy value %q, want %q", got.scfwHome, value)
	}
	if !strings.Contains(buildManagedBlock(got, false, false), "export SCFW_HOME=") {
		t.Fatal("additive update dropped export")
	}
}
