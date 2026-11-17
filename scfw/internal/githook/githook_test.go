// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package githook

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// The test binary stands in for the scfw executable that hook scripts run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "git-hook" {
		os.Exit(Run(context.Background(), os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

type recorder struct {
	mutex     sync.Mutex
	checkouts []Checkout
	err       error
}

func (r *recorder) decide(_ context.Context, checkout Checkout) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.checkouts = append(r.checkouts, checkout)
	return r.err
}

func (r *recorder) recorded() []Checkout {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]Checkout(nil), r.checkouts...)
}

// gitEnvironment keeps the host's Git configuration and hooks out of the tests.
func gitEnvironment(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git required")
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_WORK_TREE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func git(t *testing.T, dir string, env map[string]string, args ...string) (string, error) {
	t.Helper()
	child := exec.Command("git", args...)
	child.Dir = dir
	child.Env = os.Environ()
	for key, value := range env {
		child.Env = append(child.Env, key+"="+value)
	}
	output, err := child.CombinedOutput()
	return string(output), err
}

func mustGit(t *testing.T, dir string, env map[string]string, args ...string) string {
	t.Helper()
	output, err := git(t, dir, env, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(output)
}

func commit(t *testing.T, dir, message string) string {
	t.Helper()
	mustGit(t, dir, nil, "add", ".")
	mustGit(t, dir, nil, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=SCFW Test",
		"-c", "user.email=scfw@example.invalid", "commit", "-q", "-m", message)
	return mustGit(t, dir, nil, "rev-parse", "HEAD")
}

// sourceRepository returns a repository with one commit and its SHA.
func sourceRepository(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, nil, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"w","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, commit(t, dir, "fixture")
}

func startHooks(t *testing.T, decide Decide) (*Hooks, map[string]string) {
	t.Helper()
	hooks, err := Start(context.Background(), os.Args[0], decide)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hooks.Close() })
	spec := &proxy.CommandSpec{EnvOverrides: map[string]string{}}
	hooks.Apply(spec)
	return hooks, spec.EnvOverrides
}

func resolved(t *testing.T, path string) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCloneAllowedReportsCheckout(t *testing.T) {
	gitEnvironment(t)
	source, sha := sourceRepository(t)
	decisions := &recorder{}
	_, env := startHooks(t, decisions.decide)
	destination := filepath.Join(t.TempDir(), "clone")
	mustGit(t, t.TempDir(), env, "clone", "-q", "file://"+source, destination)

	checkouts := decisions.recorded()
	if len(checkouts) != 1 {
		t.Fatalf("checkouts = %+v, want one", checkouts)
	}
	got := checkouts[0]
	if resolved(t, got.Dir) != resolved(t, destination) || got.Origin != "file://"+source || got.SHA != sha {
		t.Fatalf("checkout = %+v, want dir %s, origin file://%s, sha %s", got, destination, source, sha)
	}
}

func TestCloneBlockedFailsWithMessage(t *testing.T) {
	gitEnvironment(t)
	source, _ := sourceRepository(t)
	message := "supply chain firewall blocked w 1.0.0 (file://x#y)"
	_, env := startHooks(t, (&recorder{err: errors.New(message)}).decide)
	output, err := git(t, t.TempDir(), env, "clone", "-q", "file://"+source, filepath.Join(t.TempDir(), "clone"))
	if err == nil {
		t.Fatal("clone succeeded, want the blocked checkout to fail it")
	}
	if !strings.Contains(output, message) {
		t.Fatalf("output = %q, want the block message", output)
	}
}

func TestCheckoutOfUnadvertisedSHAIsEvaluated(t *testing.T) {
	gitEnvironment(t)
	source, first := sourceRepository(t)
	if err := os.WriteFile(filepath.Join(source, "index.js"), []byte("module.exports = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commit(t, source, "second")
	decisions := &recorder{}
	_, env := startHooks(t, decisions.decide)
	// pacote's shape for a commit no ref advertises.
	target := filepath.Join(t.TempDir(), "clone")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	mustGit(t, target, env, "clone", "--mirror", "-q", "file://"+source, filepath.Join(target, ".git"))
	mustGit(t, target, env, "init", "-q")
	mustGit(t, target, env, "checkout", "-q", first)

	checkouts := decisions.recorded()
	if len(checkouts) != 1 || checkouts[0].SHA != first {
		t.Fatalf("checkouts = %+v, want one for %s", checkouts, first)
	}
}

func TestHookFailsClosedWithoutParent(t *testing.T) {
	gitEnvironment(t)
	source, sha := sourceRepository(t)
	hooks, env := startHooks(t, (&recorder{}).decide)
	// Closing removes the hooks directory, so keep a copy of the script.
	script, err := os.ReadFile(filepath.Join(env["GIT_CONFIG_VALUE_0"], "post-checkout"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "post-checkout")
	if err := os.WriteFile(copied, script, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hooks.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(copied, strings.Repeat("0", 40), sha, "1")
	child.Dir = source
	output, err := child.CombinedOutput()
	if err == nil {
		t.Fatal("hook succeeded without its parent, want it to fail closed")
	}
	if !strings.Contains(string(output), "could not evaluate git checkout") {
		t.Fatalf("output = %q", output)
	}
}

func TestApplyAppendsAfterExistingEntries(t *testing.T) {
	hooks, err := Start(context.Background(), os.Args[0], (&recorder{}).decide)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hooks.Close() }()
	spec := &proxy.CommandSpec{EnvOverrides: map[string]string{"GIT_CONFIG_COUNT": "2"}}
	hooks.Apply(spec)
	if spec.EnvOverrides["GIT_CONFIG_KEY_2"] != "core.hooksPath" || spec.EnvOverrides["GIT_CONFIG_COUNT"] != "3" {
		t.Fatalf("overrides = %v", spec.EnvOverrides)
	}
	if info, err := os.Stat(filepath.Join(spec.EnvOverrides["GIT_CONFIG_VALUE_2"], "post-checkout")); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("post-checkout hook missing or not executable: %v", err)
	}
}

// A nested scfw run stacks its hooks on the outer ones; each layer must forward
// to the layer below it rather than back up the stack.
func TestNestedHooksForwardToTheLayerBelow(t *testing.T) {
	gitEnvironment(t)
	repository, _ := sourceRepository(t)
	marker := filepath.Join(t.TempDir(), "marker")
	writeHook(t, filepath.Join(repository, ".git", "hooks"), "pre-commit", "echo ran > '"+marker+"'")
	spec := &proxy.CommandSpec{EnvOverrides: map[string]string{}}
	for range 2 {
		hooks, err := Start(context.Background(), os.Args[0], (&recorder{}).decide)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hooks.Close() })
		hooks.Apply(spec)
	}
	if err := os.WriteFile(filepath.Join(repository, "index.js"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Stage without the hooks: only the guarded commit below may loop.
	mustGit(t, repository, nil, "add", ".")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "git", "-c", "commit.gpgsign=false", "-c", "user.name=SCFW Test",
		"-c", "user.email=scfw@example.invalid", "commit", "-q", "-m", "change")
	child.Dir = repository
	child.Env = os.Environ()
	for key, value := range spec.EnvOverrides {
		child.Env = append(child.Env, key+"="+value)
	}
	// A forwarding loop spawns hook processes without end; kill the whole group.
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	child.Cancel = func() error { return syscall.Kill(-child.Process.Pid, syscall.SIGKILL) }
	output, err := child.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("nested hooks forwarded to each other without end")
	}
	if err != nil {
		t.Fatalf("commit: %v\n%s", err, output)
	}
	if !exists(marker) {
		t.Fatal("the repository's pre-commit hook did not run under nested hooks")
	}
}

// Git skips a hook it cannot execute, so Start must not rely on mode bits that
// a noexec mount would override.
func TestExecutableUsesAccessNotModeBits(t *testing.T) {
	dir := t.TempDir()
	runnable, plain := filepath.Join(dir, "runnable"), filepath.Join(dir, "plain")
	if err := os.WriteFile(runnable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !canExecute(runnable) || canExecute(plain) || canExecute(filepath.Join(dir, "missing")) {
		t.Fatalf("canExecute() = %v, %v, %v; want true, false, false",
			canExecute(runnable), canExecute(plain), canExecute(filepath.Join(dir, "missing")))
	}
}

func TestCloseRemovesHooks(t *testing.T) {
	hooks, err := Start(context.Background(), os.Args[0], (&recorder{}).decide)
	if err != nil {
		t.Fatal(err)
	}
	spec := &proxy.CommandSpec{}
	hooks.Apply(spec)
	if err := hooks.Close(); err != nil {
		t.Fatal(err)
	}
	if dir := filepath.Dir(spec.EnvOverrides["GIT_CONFIG_VALUE_0"]); exists(dir) {
		t.Fatalf("hooks directory %s remains after Close", dir)
	}
}

func writeHook(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// commitWithHooks commits without disabling hooks, unlike commit.
func commitWithHooks(t *testing.T, dir string, env map[string]string) (string, error) {
	t.Helper()
	mustGit(t, dir, env, "add", ".")
	return git(t, dir, env, "-c", "commit.gpgsign=false", "-c", "user.name=SCFW Test", "-c", "user.email=scfw@example.invalid", "commit", "-q", "-m", "change")
}

func TestUserLocalHooksPathStillRuns(t *testing.T) {
	gitEnvironment(t)
	repository, _ := sourceRepository(t)
	marker := filepath.Join(t.TempDir(), "marker")
	mustGit(t, repository, nil, "config", "core.hooksPath", ".husky")
	writeHook(t, filepath.Join(repository, ".husky"), "pre-commit", "echo ran > '"+marker+"'\nexit 3")
	_, env := startHooks(t, (&recorder{}).decide)
	if err := os.WriteFile(filepath.Join(repository, "index.js"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := commitWithHooks(t, repository, env)
	if err == nil {
		t.Fatalf("commit succeeded, want the user's failing pre-commit hook to stop it\n%s", output)
	}
	if !exists(marker) {
		t.Fatal("the user's local core.hooksPath pre-commit hook did not run")
	}
}

func TestDefaultHooksDirectoryStillRuns(t *testing.T) {
	gitEnvironment(t)
	repository, _ := sourceRepository(t)
	marker := filepath.Join(t.TempDir(), "marker")
	writeHook(t, filepath.Join(repository, ".git", "hooks"), "post-commit", "echo ran > '"+marker+"'")
	_, env := startHooks(t, (&recorder{}).decide)
	if err := os.WriteFile(filepath.Join(repository, "index.js"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := commitWithHooks(t, repository, env); err != nil {
		t.Fatalf("commit: %v\n%s", err, output)
	}
	if !exists(marker) {
		t.Fatal("the repository's .git/hooks post-commit hook did not run")
	}
}

func TestGlobalHooksPathRunsAfterAllowedClone(t *testing.T) {
	gitEnvironment(t)
	source, _ := sourceRepository(t)
	global := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	writeHook(t, filepath.Join(global, "hooks"), "post-checkout", "echo ran > '"+marker+"'")
	config := filepath.Join(global, "gitconfig")
	if err := os.WriteFile(config, []byte("[core]\n\thooksPath = "+filepath.Join(global, "hooks")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", config)
	_, env := startHooks(t, (&recorder{}).decide)
	mustGit(t, t.TempDir(), env, "clone", "-q", "file://"+source, filepath.Join(t.TempDir(), "clone"))
	if !exists(marker) {
		t.Fatal("the global core.hooksPath post-checkout hook did not run after an allowed clone")
	}
}

func TestSubmoduleCheckoutIsNotEvaluated(t *testing.T) {
	gitEnvironment(t)
	submodule, _ := sourceRepository(t)
	superproject, _ := sourceRepository(t)
	mustGit(t, superproject, nil, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+submodule, "vendor")
	commit(t, superproject, "add submodule")
	decisions := &recorder{}
	_, env := startHooks(t, decisions.decide)
	destination := filepath.Join(t.TempDir(), "clone")
	mustGit(t, t.TempDir(), env, "-c", "protocol.file.allow=always", "clone", "-q", "--recurse-submodules", "file://"+superproject, destination)

	checkouts := decisions.recorded()
	if len(checkouts) != 1 || resolved(t, checkouts[0].Dir) != resolved(t, destination) {
		t.Fatalf("checkouts = %+v, want only the superproject %s", checkouts, destination)
	}
}

func TestFileCheckoutIsNotEvaluated(t *testing.T) {
	gitEnvironment(t)
	source, _ := sourceRepository(t)
	decisions := &recorder{}
	_, env := startHooks(t, decisions.decide)
	destination := filepath.Join(t.TempDir(), "clone")
	mustGit(t, t.TempDir(), env, "clone", "-q", "file://"+source, destination)
	if err := os.WriteFile(filepath.Join(destination, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, destination, env, "checkout", "--", "package.json")
	if checkouts := decisions.recorded(); len(checkouts) != 1 {
		t.Fatalf("checkouts = %+v, want only the clone", checkouts)
	}
}
