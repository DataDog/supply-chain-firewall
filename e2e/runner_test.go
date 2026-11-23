//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

type inputs struct {
	Cell                      cell
	Cases                     []plannedCase
	Binary, Discovery, Output string
}
type caseRun struct {
	Context               context.Context
	Cell                  cell
	Spec                  scenario
	Candidate             candidate
	Root, WorkDir, Binary string
	Env                   map[string]string
	Result                *result
}

func (r *caseRun) Command(label string, argv ...string) (commandEvidence, error) {
	return r.CommandInput(label, "", argv...)
}
func (r *caseRun) CommandInput(label, input string, argv ...string) (commandEvidence, error) {
	output := filepath.Join(r.Root, "commands", fmt.Sprintf("%02d-%s", len(r.Result.Commands), label))
	ev, err := executeCommand(r.Context, output, r.Env, r.WorkDir, input, argv...)
	r.Result.Commands = append(r.Result.Commands, ev)
	if len(argv) > 0 && argv[0] == r.Binary {
		r.Result.SCFWExit, r.Result.SCFWSignal = ev.ExitCode, ev.Signal
	}
	return ev, err
}
func (r *caseRun) Keep(label, path string) error {
	ev, err := digestFile(path)
	if err == nil {
		r.Result.Evidence[label] = ev
	}
	return err
}
func digestFile(path string) (fileEvidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileEvidence{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fileEvidence{}, err
	}
	return fileEvidence{Path: path, SHA256: fmt.Sprintf("%x", h.Sum(nil))}, nil
}
func isolatedEnvironment(root string) (map[string]string, error) {
	env := map[string]string{"PATH": os.Getenv("PATH"), "LANG": "C.UTF-8", "TZ": "UTC", "SCFW_MODE": "local", "SCFW_VERBOSE": "1", "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": os.DevNull, "PIP_INDEX_URL": "https://pypi.org/simple", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "GIT_CONFIG_NOSYSTEM": "1"}
	for key, dir := range map[string]string{"HOME": "home", "XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache", "XDG_DATA_HOME": "data", "TMPDIR": "tmp", "SCFW_HOME": "scfw", "PIP_CACHE_DIR": "cache/pip"} {
		env[key] = filepath.Join(root, dir)
		if err := os.MkdirAll(env[key], 0700); err != nil {
			return nil, err
		}
	}
	env["SCFW_LOG_FILE"] = filepath.Join(root, "policy.jsonl")
	env["GIT_CONFIG_GLOBAL"] = os.DevNull
	return env, os.MkdirAll(filepath.Join(root, "work"), 0700)
}
func runCommand(ctx context.Context, output string, env map[string]string, cwd string, argv ...string) (commandEvidence, error) {
	return executeCommand(ctx, output, env, cwd, "", argv...)
}
func executeCommand(ctx context.Context, output string, env map[string]string, cwd, input string, argv ...string) (commandEvidence, error) {
	ev := commandEvidence{Argv: slices.Clone(argv), Environment: map[string]string{}, Cwd: cwd, StartedAt: time.Now().UTC(), ExitCode: -1}
	// Only known non-secret harness values are retained. Recipes may add credentials later.
	for _, key := range []string{"PATH", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "SCFW_HOME", "SCFW_MODE", "SCFW_PROXY_ENABLED", "SCFW_LOG_FILE", "PIP_CONFIG_FILE"} {
		if value, ok := env[key]; ok {
			ev.Environment[key] = value
		}
	}
	if len(argv) == 0 {
		return ev, fmt.Errorf("empty command")
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return ev, err
	}
	stdout, err := os.Create(filepath.Join(output, "stdout"))
	if err != nil {
		return ev, err
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(output, "stderr"))
	if err != nil {
		return ev, err
	}
	defer stderr.Close()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.Stdin = cwd, stdout, stderr, strings.NewReader(input)
	for _, key := range slices.Sorted(maps.Keys(env)) {
		cmd.Env = append(cmd.Env, key+"="+env[key])
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	err = cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	ev.EndedAt, ev.TimedOut = time.Now().UTC(), ctx.Err() != nil
	if cmd.ProcessState != nil {
		ev.ExitCode = cmd.ProcessState.ExitCode()
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			ev.Signal = status.Signal().String()
		}
	}
	var evidenceErr error
	ev.Stdout, evidenceErr = digestFile(stdout.Name())
	if evidenceErr != nil {
		return ev, evidenceErr
	}
	ev.Stderr, evidenceErr = digestFile(stderr.Name())
	if evidenceErr != nil {
		return ev, evidenceErr
	}
	if ev.TimedOut {
		return ev, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("command timed out: %w", ctx.Err()))
	}
	return ev, err
}
func loadInputs() (inputs, error) {
	in := inputs{Binary: os.Getenv("SCFW_E2E_BINARY"), Discovery: os.Getenv("SCFW_E2E_DISCOVERY"), Output: os.Getenv("SCFW_E2E_OUTPUT")}
	manifest := os.Getenv("SCFW_E2E_MATRIX")
	for _, path := range []string{manifest, in.Discovery, in.Output} {
		if err := requireAbsolute(path); err != nil {
			return in, err
		}
	}
	source, err := filepath.Abs("..")
	if err != nil {
		return in, err
	}
	if rel, err := filepath.Rel(source, in.Output); err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return in, fmt.Errorf("evidence directory must be outside the source tree")
	}
	var m matrix
	if err := readJSON(manifest, &m); err != nil {
		return in, err
	}
	if m.SchemaVersion != schemaVersion {
		return in, fmt.Errorf("unsupported matrix schema %d", m.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, c := range m.Cells {
		if !validIDComponent(c.ID) || seen[c.ID] {
			return in, fmt.Errorf("invalid or duplicate cell ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.ID == os.Getenv("SCFW_E2E_CELL") {
			in.Cell = c
		}
	}
	if in.Cell.ID == "" {
		return in, fmt.Errorf("unknown or unset SCFW_E2E_CELL")
	}
	in.Cases, err = selectCases(in.Cell, strings.Split(os.Getenv("SCFW_E2E_SUITES"), ","))
	return in, err
}
func TestPlan(t *testing.T) {
	in, err := loadInputs()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(in.Output, "planned.json"), struct {
		SchemaVersion int           `json:"schema_version"`
		Cases         []plannedCase `json:"cases"`
	}{schemaVersion, in.Cases}); err != nil {
		t.Fatal(err)
	}
}
func TestDiscover(t *testing.T) {
	in, err := loadInputs()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in.Discovery); !os.IsNotExist(err) {
		t.Fatal("discovery output already exists; preserve the first run and choose a new path")
	}
	d := discovery{SchemaVersion: schemaVersion, ID: time.Now().UTC().Format("20060102T150405.000000000Z"), Candidates: map[string]candidate{}}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	for _, spec := range in.Cases {
		if spec.NotApplicable != "" || spec.DiscoveryKey == "" {
			continue
		}
		if _, exists := d.Candidates[spec.DiscoveryKey]; exists {
			continue
		}
		discover, exists := discoverers[spec.DiscoveryKey]
		if !exists {
			t.Fatalf("no discoverer for %s", spec.DiscoveryKey)
		}
		candidate, err := discover(ctx, in.Cell, filepath.Join(in.Output, "discovery", spec.DiscoveryKey))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateCandidate(candidate, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		d.Candidates[spec.DiscoveryKey] = candidate
	}
	if err := writeJSON(in.Discovery, d); err != nil {
		t.Fatal(err)
	}
}
func preflight(in inputs) (fileEvidence, error) {
	if in.Cell.OS != runtime.GOOS || in.Cell.Arch != runtime.GOARCH {
		return fileEvidence{}, fmt.Errorf("cell requires native %s/%s; host is %s/%s", in.Cell.OS, in.Cell.Arch, runtime.GOOS, runtime.GOARCH)
	}
	for _, path := range []string{in.Binary, in.Cell.Executable, in.Cell.Runtime, in.Cell.Git} {
		if err := requireAbsolute(path); err != nil {
			return fileEvidence{}, err
		}
	}
	info, err := buildinfo.ReadFile(in.Binary)
	if err != nil {
		return fileEvidence{}, err
	}
	trimpath := false
	for _, setting := range info.Settings {
		if setting.Key == "-trimpath" && setting.Value == "true" {
			trimpath = true
		}
	}
	if info.Path != "github.com/DataDog/supply-chain-firewall/scfw" || !trimpath {
		return fileEvidence{}, fmt.Errorf("supply the SCFW GoReleaser artifact with release build settings")
	}
	root := filepath.Join(in.Output, "preflight")
	env, err := isolatedEnvironment(root)
	if err != nil {
		return fileEvidence{}, err
	}
	env["PATH"] = filepath.Dir(in.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(in.Cell.Runtime) + string(os.PathListSeparator) + env["PATH"]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i, tool := range []struct{ path, pin string }{{in.Cell.Executable, in.Cell.ManagerVersion}, {in.Cell.Runtime, in.Cell.RuntimeVersion}, {in.Cell.Git, in.Cell.GitVersion}} {
		if tool.pin == "" {
			return fileEvidence{}, fmt.Errorf("missing exact version pin for %s", tool.path)
		}
		ev, err := runCommand(ctx, filepath.Join(root, fmt.Sprint(i)), env, root, tool.path, "--version")
		if err != nil {
			return fileEvidence{}, err
		}
		output, err := os.ReadFile(ev.Stdout.Path)
		if err != nil {
			return fileEvidence{}, err
		}
		stderr, err := os.ReadFile(ev.Stderr.Path)
		if err != nil {
			return fileEvidence{}, err
		}
		output = append(output, stderr...)
		if !regexp.MustCompile(`(^|[\s(v])` + regexp.QuoteMeta(tool.pin) + `($|[\s)])`).Match(output) {
			return fileEvidence{}, fmt.Errorf("version mismatch for %s: want %s, got %s", tool.path, tool.pin, output)
		}
	}
	version, err := runCommand(ctx, filepath.Join(root, "scfw-version"), env, root, in.Binary, "--version")
	if err != nil {
		return fileEvidence{}, err
	}
	versionText, err := os.ReadFile(version.Stdout.Path)
	if err != nil {
		return fileEvidence{}, err
	}
	if !regexp.MustCompile(`^scfw version \d+\.\d+\.\d+`).Match(versionText) {
		return fileEvidence{}, fmt.Errorf("SCFW version is not a release/snapshot version: %s", versionText)
	}
	if _, err := runCommand(ctx, filepath.Join(root, "os-version"), env, root, "/usr/bin/uname", "-sr"); err != nil {
		return fileEvidence{}, err
	}
	return digestFile(in.Binary)
}
func TestE2E(t *testing.T) {
	in, err := loadInputs()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(in.Output, "results.json")); !os.IsNotExist(err) {
		t.Fatal("results already exist; use a fresh output directory")
	}
	var d discovery
	if err := readJSON(in.Discovery, &d); err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != schemaVersion || d.ID == "" {
		t.Fatal("invalid discovery schema or ID")
	}
	binary, preflightErr := preflight(in)
	results := make([]result, 0, len(in.Cases))
	for _, spec := range in.Cases {
		r := result{SchemaVersion: schemaVersion, ID: spec.ID, Cell: in.Cell, Spec: spec.scenario, Artifact: binary, DiscoveryID: d.ID, StartedAt: time.Now().UTC(), Status: "PASS", Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}
		executed := false
		t.Run(spec.Scenario+"/"+spec.Variant, func(t *testing.T) {
			executed = true
			if spec.NotApplicable != "" {
				r.Status, r.Reason = "N/A", spec.NotApplicable
				return
			}
			err := classified("INFRASTRUCTURE_FAILURE", preflightErr)
			if err == nil {
				err = executeCase(t.Context(), in, spec, d, &r)
			}
			if err != nil {
				r.Status, r.Reason = "FAIL", err.Error()
				var failure caseFailure
				if errors.As(err, &failure) {
					r.Status = failure.status
				}
				t.Error(r.Status + ": " + r.Reason)
			}
		})
		if !executed {
			r.Status, r.Reason = "INFRASTRUCTURE_FAILURE", "planned case was not executed; Go subtest filters cannot omit mandatory cases"
		}
		r.EndedAt = time.Now().UTC()
		results = append(results, r)
	}
	if err := writeJSON(filepath.Join(in.Output, "results.json"), struct {
		SchemaVersion int      `json:"schema_version"`
		Results       []result `json:"results"`
	}{schemaVersion, results}); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(in.Cases, results); err != nil {
		t.Error(err)
	}
}
func executeCase(ctx context.Context, in inputs, spec plannedCase, d discovery, result *result) (caseErr error) {
	root := filepath.Join(in.Output, "cases", filepath.FromSlash(spec.ID))
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("case output already exists: %s", root))
	}
	env, err := isolatedEnvironment(root)
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	// Keep Unix socket names short even when evidence lives beneath long case
	// identities. Only the private alias lives in /tmp; all bytes stay in root.
	// Both supported operating systems provide /tmp. Using the caller's TMPDIR
	// here could repeat the same long-path problem.
	alias, err := os.MkdirTemp("/tmp", "scfw-e2e-")
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	defer func() {
		if err := os.RemoveAll(alias); err != nil {
			caseErr = errors.Join(caseErr, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("remove temporary alias: %w", err)))
		}
	}()
	if err := os.Symlink(root, filepath.Join(alias, "case")); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	// The final component is a directory, so WalkDir cleanup assertions still
	// traverse its contents instead of stopping at a root symlink.
	env["TMPDIR"] = filepath.Join(alias, "case", "tmp")
	ctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	c := d.Candidates[spec.DiscoveryKey]
	if spec.DiscoveryKey != "" {
		if err := validateCandidate(c, time.Now().UTC()); err != nil {
			return classified("PRECONDITION_UNAVAILABLE", err)
		}
		check, ok := revalidators[spec.DiscoveryKey]
		if !ok {
			return fmt.Errorf("no revalidator for %s", spec.DiscoveryKey)
		}
		if err := check(ctx, c, filepath.Join(root, "revalidation")); err != nil {
			return err
		}
	}
	env["PATH"] = filepath.Dir(in.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(in.Cell.Runtime) + string(os.PathListSeparator) + env["PATH"]
	run := &caseRun{Context: ctx, Cell: in.Cell, Spec: spec.scenario, Candidate: c, Root: root, WorkDir: filepath.Join(root, "work"), Binary: in.Binary, Env: env, Result: result}
	return spec.Run(run)
}
