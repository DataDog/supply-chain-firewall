// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
)

// npmGitDependency returns a git+file dependency on a repository built from
// testdata/npm/git-package, its HEAD commit, and the prepare script's marker.
func npmGitDependency(t *testing.T) (spec, sha, marker string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git required for npm git dependency tests")
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	repository := t.TempDir()
	if err := os.WriteFile(filepath.Join(repository, "package.json"), []byte(readProxyFixture(t, "npm/git-package/package.json")), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=SCFW Test", "-c", "user.email=scfw@example.invalid", "commit", "-q", "-m", "fixture"}} {
		child := exec.Command("git", args...)
		child.Dir = repository
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	output, err := exec.Command("git", "-C", repository, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	marker = filepath.Join(t.TempDir(), "prepare-marker")
	t.Setenv("SCFW_TEST_PREPARE_MARKER", marker)
	return "git+file://" + repository, strings.TrimSpace(string(output)), marker
}

func TestNpmGitDependencyAllowed(t *testing.T) {
	spec, sha, _ := npmGitDependency(t)
	dir := newNpmTestProject(t, startNpmRegistry(t), "")
	run := runNpmGitThroughProxy(t, []string{"install", spec}, evaluation.OutcomeAllow)
	if run.commandErr != nil {
		t.Fatalf("npm install failed: %v\n%s", run.commandErr, run.details)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg", "package.json")); err != nil {
		t.Fatalf("git dependency not installed: %v", err)
	}
	// npm clones a git dependency more than once; each checkout shares one decision.
	if run.calls != 1 {
		t.Fatalf("evaluator calls = %d, want 1 (sources %v)", run.calls, run.sources)
	}
	if want := strings.TrimPrefix(spec, "git+") + "#" + sha; !slices.Equal(run.sources, []string{want}) {
		t.Fatalf("sources = %v, want [%s]", run.sources, want)
	}
	assertProxyCleaned(t, run.config)
}

func TestNpmGitDependencyBlocked(t *testing.T) {
	spec, _, marker := npmGitDependency(t)
	dir := newNpmTestProject(t, startNpmRegistry(t), "")
	run := runNpmGitThroughProxy(t, []string{"install", spec}, evaluation.OutcomeBlock)
	assertNpmFailed(t, run.commandErr)
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg")); err == nil {
		t.Fatal("blocked git dependency was installed")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("blocked git dependency's prepare script ran")
	}
	if !strings.Contains(npmDebugLogs(t), "supply chain firewall blocked lab-git-pkg 1.0.0") {
		t.Fatal("npm's output does not contain the block message")
	}
}

func TestNpmGitDependencyWarnContinues(t *testing.T) {
	spec, _, _ := npmGitDependency(t)
	dir := newNpmTestProject(t, startNpmRegistry(t), "")
	run := runNpmGitThroughProxy(t, []string{"install", spec}, evaluation.OutcomeWarn)
	if run.commandErr != nil {
		t.Fatalf("npm install failed: %v", run.commandErr)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg", "package.json")); err != nil {
		t.Fatalf("git dependency not installed: %v", err)
	}
}

// npmDebugLogs returns npm's debug logs from the test cache, which record the
// git command's stderr when the command fails.
func npmDebugLogs(t *testing.T) string {
	t.Helper()
	logs, err := filepath.Glob(filepath.Join(os.Getenv("npm_config_cache"), "_logs", "*.log"))
	if err != nil {
		t.Fatal(err)
	}
	var content strings.Builder
	for _, log := range logs {
		data, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		content.Write(data)
	}
	return content.String()
}

func TestRunRegistersGitHookCommand(t *testing.T) {
	for _, command := range RootCmd().Commands() {
		if command.Name() == "git-hook" {
			if !command.Hidden {
				t.Fatal("git-hook must be hidden")
			}
			return
		}
	}
	t.Fatal("RootCmd has no git-hook command")
}
