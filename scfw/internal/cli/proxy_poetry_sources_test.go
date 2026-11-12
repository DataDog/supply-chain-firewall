// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPoetryRunPreservesChildOptions(t *testing.T) {
	manager := poetryForProxyTest(t)
	root := t.TempDir()
	poetryTestFile(t, filepath.Join(root, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
	poetryTestFile(t, filepath.Join(root, "child-options.py"), readProxyFixture(t, "poetry/child-options.py"))
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	poetryTestFile(t, filepath.Join(child, "pyproject.toml"), readProxyFixture(t, "poetry/invalid.lock"))
	t.Chdir(root)
	for _, prefix := range [][]string{{"run"}, {"--directory", root, "run"}, {"run", "--directory", root}} {
		args := append(append([]string{}, prefix...), "python", filepath.Join(root, "child-options.py"), "-P", "child", "--project=child", "-Cchild", "--directory", "child")
		output := filepath.Join(root, "child-output.json")
		t.Setenv("SCFW_TEST_CHILD_OUTPUT", output)
		if err := manager.RunCommand(context.Background(), args); err != nil {
			t.Fatalf("direct Poetry: %v", err)
		}
		expected, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(output); err != nil {
			t.Fatal(err)
		}
		runner := &capturingPoetryRunner{Poetry: manager}
		commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
		if commandErr != nil || setupErr != nil {
			t.Fatalf("proxied child options: %v / %v", commandErr, setupErr)
		}
		actual, err := os.ReadFile(output)
		if err != nil || string(actual) != string(expected) {
			t.Fatalf("child arguments or working directory changed: %s / %s / %v", actual, expected, err)
		}
		assertProxyCleaned(t, runner.config)
	}
}
