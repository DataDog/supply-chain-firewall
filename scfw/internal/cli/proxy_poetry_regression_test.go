// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPoetryRegeneratesIgnoredLockThroughProxy(t *testing.T) {
	manager := poetryForProxyTest(t)
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprintf("oversized=%t", oversized), func(t *testing.T) {
			root := t.TempDir()
			manifest := readProxyFixture(t, "poetry/git-pyproject.toml")
			poetryTestFile(t, filepath.Join(root, "pyproject.toml"), manifest)
			old := []byte(readProxyFixture(t, "poetry/invalid.lock"))
			if oversized {
				old = bytes.Repeat([]byte("# ignored lock\n"), (4<<20)/14+1)
			}
			lock := filepath.Join(root, "poetry.lock")
			if err := os.WriteFile(lock, old, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--directory", root, "--no-interaction", "lock", "--regenerate"}
			if _, err := manager.PyPIClassifierOptions(args); err != nil {
				t.Fatal(err)
			}
			runner := &capturingPoetryRunner{Poetry: manager}
			commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
			if commandErr != nil || setupErr != nil {
				t.Fatalf("regeneration failed: %v / %v", commandErr, setupErr)
			}
			data, err := os.ReadFile(lock)
			if err != nil || bytes.Equal(data, old) || !bytes.Contains(data, []byte("lock-version")) {
				t.Fatal("Poetry did not regenerate the lockfile")
			}
			data, err = os.ReadFile(filepath.Join(root, "pyproject.toml"))
			if err != nil || string(data) != manifest {
				t.Fatal("regeneration changed the project configuration")
			}
			assertProxyCleaned(t, runner.config)
		})
	}
}
