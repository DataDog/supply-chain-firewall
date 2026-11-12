// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/pnpm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// forEachPnpm runs test against every real pnpm release named by
// SCFW_TEST_PNPM_<major>; CI pins 10.34.9, 11.28.9, and 12.18.0.
func forEachPnpm(t *testing.T, test func(t *testing.T, major int, executable string)) {
	t.Helper()
	for _, major := range []int{10, 11, 12} {
		t.Run(fmt.Sprintf("pnpm%d", major), func(t *testing.T) {
			variable := fmt.Sprintf("SCFW_TEST_PNPM_%d", major)
			executable := os.Getenv(variable)
			if executable == "" {
				t.Skip(variable + " required for pnpm integration tests")
			}
			test(t, major, executable)
		})
	}
}

// newPnpmTestProject isolates pnpm from the host and enters a project whose
// .npmrc selects the test registry and trusts its certificate.
func newPnpmTestProject(t *testing.T, registry *npmTestRegistry, npmrcExtra string) string {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(lower, "pnpm_config_") || strings.HasSuffix(lower, "_proxy") ||
			lower == "proxy" || strings.HasPrefix(key, "XDG_") || strings.HasPrefix(key, "COREPACK_") ||
			slices.Contains([]string{"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "PREFIX", "DESTDIR", "NODE_OPTIONS", "PNPM_HOME", "CI"}, key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	for key, value := range map[string]string{
		"HOME": filepath.Join(root, "home"), "PREFIX": filepath.Join(root, "prefix"), "PNPM_HOME": filepath.Join(root, "pnpm-home"),
		"XDG_CONFIG_HOME": filepath.Join(root, "config"), "XDG_CACHE_HOME": filepath.Join(root, "cache"),
		"XDG_DATA_HOME": filepath.Join(root, "data"), "XDG_STATE_HOME": filepath.Join(root, "state"),
		"npm_config_update_notifier": "false", "pnpm_config_update_notifier": "false",
	} {
		t.Setenv(key, value)
	}
	usePnpmStore(t, filepath.Join(root, "store"))
	dir := filepath.Join(root, "project")
	writeNpmProject(t, dir, readProxyFixture(t, "npm/project/package.json"), "registry="+registry.URL+"/\ncafile="+registry.CAPath+"\n"+npmrcExtra)
	t.Chdir(dir)
	return dir
}

// usePnpmStore selects pnpm's content-addressable store; pnpm 10 reads npm_config_*
// and pnpm 11 and 12 read pnpm_config_*.
func usePnpmStore(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("npm_config_store_dir", dir)
	t.Setenv("pnpm_config_store_dir", dir)
}

type capturingPnpmRunner struct {
	pnpm.Pnpm
	capture func(proxy.ClientConfig)
}

func (r capturingPnpmRunner) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	r.capture(config)
	return r.Pnpm.ProxyCommand(ctx, args, config)
}

type pnpmProxyRun struct {
	commandErr, setupErr error
	calls                int32
	details              string
	config               proxy.ClientConfig
}

func runPnpmThroughProxy(t *testing.T, executable string, args []string, outcome evaluation.Outcome) pnpmProxyRun {
	t.Helper()
	manager, err := pnpm.NewPnpm(context.Background(), "pnpm", executable)
	if err != nil {
		t.Fatal(err)
	}
	var run pnpmProxyRun
	var calls atomic.Int32
	var details bytes.Buffer
	evaluator := proxyEvaluatorFunc(func(_ context.Context, interactive bool, _ *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		calls.Add(1)
		if interactive {
			t.Error("proxy evaluation must not prompt")
		}
		return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome}, nil
	})
	configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
		packageEvaluator := newProxyPackageEvaluator(ctx, time.Now(), append([]string{"pnpm"}, args...), "pnpm", manager.Executable(), "", evaluator, nopReporter{}, &details)
		hook, err := newNpmProxyHook(ctx, manager, args, client, packageEvaluator.evaluatePackage)
		return []proxy.RequestHook{hook}, err
	}
	runner := capturingPnpmRunner{Pnpm: manager, capture: func(config proxy.ClientConfig) { run.config = config }}
	run.commandErr, run.setupErr = runThroughProxy(context.Background(), runner, args, configure)
	run.calls, run.details = calls.Load(), details.String()
	return run
}

func assertPnpmSucceeded(t *testing.T, run pnpmProxyRun) {
	t.Helper()
	if run.setupErr != nil || run.commandErr != nil {
		t.Fatalf("pnpm failed: setup %v, command %v", run.setupErr, run.commandErr)
	}
}

func assertPnpmFailed(t *testing.T, run pnpmProxyRun) {
	t.Helper()
	if run.setupErr != nil {
		t.Fatalf("setup error = %v, want pnpm to run and fail", run.setupErr)
	}
	assertNpmFailed(t, run.commandErr)
}

// seedPnpmLockfile installs lab-pkg once, then leaves only the manifest and
// lockfile, with an empty store, so the next command downloads it again.
func seedPnpmLockfile(t *testing.T, executable, dir string) {
	t.Helper()
	assertPnpmSucceeded(t, runPnpmThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow))
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	usePnpmStore(t, t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

func TestPnpmProxyEndToEnd(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		for _, test := range []struct {
			name    string
			args    []string
			seed    bool
			outcome evaluation.Outcome
			// hits is the number of tarball downloads the run itself may make.
			hits, calls int32
			failed      bool
		}{
			{name: "add-allow", args: []string{"add", "lab-pkg"}, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
			{name: "add-block", args: []string{"add", "lab-pkg"}, outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
			{name: "warn-continues", args: []string{"add", "lab-pkg"}, outcome: evaluation.OutcomeWarn, hits: 1, calls: 1},
			{name: "pnpm-failure", args: []string{"add", "does-not-exist"}, outcome: evaluation.OutcomeAllow, failed: true},
			{name: "frozen-lockfile-block", args: []string{"install", "--frozen-lockfile"}, seed: true,
				outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
			{name: "install-allow", args: []string{"install"}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
			{name: "update-allow", args: []string{"update"}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
			{name: "options-before-command", args: []string{"--dir", ".", "add", "lab-pkg"},
				outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				dir := newPnpmTestProject(t, registry, "")
				npmrc, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
				if err != nil {
					t.Fatal(err)
				}
				if test.seed {
					seedPnpmLockfile(t, executable, dir)
				}
				manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
				if err != nil {
					t.Fatal(err)
				}
				lockfile, lockErr := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
				before := registry.TarballHits.Load()
				run := runPnpmThroughProxy(t, executable, test.args, test.outcome)
				if test.failed {
					assertPnpmFailed(t, run)
				} else {
					assertPnpmSucceeded(t, run)
				}
				if hits := registry.TarballHits.Load() - before; hits != test.hits {
					t.Fatalf("tarball downloads = %d, want %d", hits, test.hits)
				}
				if run.calls != test.calls {
					t.Fatalf("evaluations = %d, want %d", run.calls, test.calls)
				}
				if test.outcome == evaluation.OutcomeWarn && (!strings.Contains(run.details, "WARN") || strings.Contains(run.details, "Proceed")) {
					t.Fatalf("unexpected warning output: %s", run.details)
				}
				if test.failed {
					after, err := os.ReadFile(filepath.Join(dir, "package.json"))
					afterLock, afterLockErr := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
					if err != nil || !bytes.Equal(after, manifest) || (afterLockErr == nil) != (lockErr == nil) || !bytes.Equal(afterLock, lockfile) {
						t.Fatal("a failed command changed package.json or pnpm-lock.yaml")
					}
				} else {
					if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
						t.Fatalf("package not installed: %v", err)
					}
					if entries, err := os.ReadDir(os.Getenv("pnpm_config_store_dir")); err != nil || len(entries) == 0 {
						t.Fatalf("pnpm did not use its configured store: %v", err)
					}
				}
				if after, err := os.ReadFile(filepath.Join(dir, ".npmrc")); err != nil || !bytes.Equal(after, npmrc) {
					t.Fatalf(".npmrc changed: %q (error %v)", after, err)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}
