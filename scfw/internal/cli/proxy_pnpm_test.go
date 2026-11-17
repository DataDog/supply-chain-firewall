// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
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
	// pnpm dlx resolves its cache under the home directory.
	if err := os.MkdirAll(filepath.Join(root, "home"), 0700); err != nil {
		t.Fatal(err)
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
	return runPnpmNamedThroughProxy(t, "pnpm", executable, args, outcome)
}

func runPnpmNamedThroughProxy(t *testing.T, name, executable string, args []string, outcome evaluation.Outcome) pnpmProxyRun {
	t.Helper()
	manager, err := pnpm.NewPnpm(context.Background(), name, executable)
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

func writePnpmFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// Every way a user can point pnpm elsewhere must still leave the tarball
// download evaluated and blocked.
func TestPnpmBypassAttemptsAreStillEvaluated(t *testing.T) {
	workspaceSetting := readProxyFixture(t, "pnpm/workspace-setting.yaml.tmpl")
	configSetting := readProxyFixture(t, "pnpm/config-setting.yaml.tmpl")
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		for _, test := range []struct {
			name   string
			majors []int
			npmrc  func(tunnel string) string
			// workspace is the project's pnpm-workspace.yaml; global is config.yaml.
			workspace, global func(tunnel string) string
			env               func(tunnel string) [2]string
			args              func(tunnel string) []string
		}{
			{name: "npmrc https-proxy", npmrc: func(tunnel string) string { return "https-proxy=" + tunnel + "\n" }},
			{name: "npmrc noproxy", npmrc: func(string) string { return "noproxy=localhost\n" }},
			{name: "npmrc no-proxy", npmrc: func(string) string { return "no-proxy=localhost\n" }},
			{name: "npmrc strict-ssl false", npmrc: func(string) string { return "strict-ssl=false\n" }},
			{name: "workspace httpsProxy", workspace: func(tunnel string) string { return fmt.Sprintf(workspaceSetting, "httpsProxy", tunnel) }},
			{name: "workspace noProxy", workspace: func(string) string { return fmt.Sprintf(workspaceSetting, "noProxy", "localhost") }},
			{name: "config.yaml noProxy", majors: []int{11, 12}, global: func(string) string { return fmt.Sprintf(configSetting, "noProxy", "localhost") }},
			{name: "env npm_config_https_proxy", env: func(tunnel string) [2]string { return [2]string{"npm_config_https_proxy", tunnel} }},
			{name: "env pnpm_config_https_proxy", env: func(tunnel string) [2]string { return [2]string{"pnpm_config_https_proxy", tunnel} }},
			{name: "env PNPM_CONFIG_NOPROXY", env: func(string) [2]string { return [2]string{"PNPM_CONFIG_NOPROXY", "localhost"} }},
			{name: "env NO_PROXY", env: func(string) [2]string { return [2]string{"NO_PROXY", "localhost"} }},
			{name: "env No_Proxy", env: func(string) [2]string { return [2]string{"No_Proxy", "localhost"} }},
			{name: "option config.https-proxy", args: func(tunnel string) []string { return []string{"--config.https-proxy=" + tunnel} }},
			{name: "option https-proxy", args: func(tunnel string) []string { return []string{"--https-proxy", tunnel} }},
			{name: "option config.noproxy", args: func(string) []string { return []string{"--config.noproxy=localhost"} }},
		} {
			if test.majors != nil && !slices.Contains(test.majors, major) {
				continue
			}
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				var hits atomic.Int32
				upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &hits})
				tunnel := strings.Replace(upstream.URL, "://", "://proxy:secret@", 1)
				extra := ""
				if test.npmrc != nil {
					extra = test.npmrc(tunnel)
				}
				dir := newPnpmTestProject(t, registry, extra)
				args := []string{"add", "lab-pkg"}
				if test.workspace != nil {
					writePnpmFile(t, filepath.Join(dir, "pnpm-workspace.yaml"), test.workspace(tunnel))
					args = []string{"add", "-w", "lab-pkg"}
				}
				if test.global != nil {
					writePnpmFile(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "pnpm", "config.yaml"), test.global(tunnel))
				}
				if test.env != nil {
					pair := test.env(tunnel)
					t.Setenv(pair[0], pair[1])
				}
				if test.args != nil {
					args = append(args, test.args(tunnel)...)
				}
				run := runPnpmThroughProxy(t, executable, args, evaluation.OutcomeBlock)
				assertPnpmFailed(t, run)
				if run.calls != 1 || registry.TarballHits.Load() != 0 {
					t.Fatalf("evaluations=%d tarball downloads=%d, want the tarball evaluated and blocked", run.calls, registry.TarballHits.Load())
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

func TestPnpmChainsToAuthenticatedUpstream(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		registry := startNpmRegistry(t)
		var tunnels atomic.Int32
		tunnel := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
		newPnpmTestProject(t, registry, "")
		t.Setenv("HTTPS_PROXY", strings.Replace(tunnel.URL, "://", "://proxy:secret@", 1))
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(previous) })

		run := runPnpmThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
		assertPnpmSucceeded(t, run)
		if tunnels.Load() < 1 || registry.TarballHits.Load() != 1 || run.calls != 1 {
			t.Fatalf("tunnels=%d tarball downloads=%d evaluations=%d", tunnels.Load(), registry.TarballHits.Load(), run.calls)
		}
		for _, output := range []string{logs.String(), run.details} {
			if strings.Contains(output, "secret") {
				t.Fatalf("upstream credential leaked: %s", output)
			}
		}
		assertProxyCleaned(t, run.config)
	})
}

func TestPnpmWithoutUpstreamConnectsDirectly(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		registry := startNpmRegistry(t)
		var tunnels atomic.Int32
		proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
		newPnpmTestProject(t, registry, "")
		run := runPnpmThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
		assertPnpmSucceeded(t, run)
		if tunnels.Load() != 0 || registry.TarballHits.Load() != 1 {
			t.Fatalf("tunnels=%d tarball downloads=%d, want a direct download", tunnels.Load(), registry.TarballHits.Load())
		}
	})
}

// writePnpmWorkspace turns dir into a workspace with members a and b.
func writePnpmWorkspace(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		writePnpmFile(t, filepath.Join(dir, path), content)
	}
}

func TestPnpmWorkspaceEndToEnd(t *testing.T) {
	files := map[string]string{}
	for _, path := range []string{"pnpm-workspace.yaml", "packages/a/package.json", "packages/b/package.json"} {
		files[path] = readProxyFixture(t, filepath.Join("pnpm", "workspace", path))
	}
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		for _, test := range []struct {
			name    string
			args    []string
			seed    bool
			outcome evaluation.Outcome
			failed  bool
		}{
			{name: "filter-allow", args: []string{"--filter", "a", "add", "lab-pkg"}, outcome: evaluation.OutcomeAllow},
			{name: "filter-block", args: []string{"--filter", "a", "add", "lab-pkg"}, outcome: evaluation.OutcomeBlock, failed: true},
			{name: "dir-allow", args: []string{"-C", "packages/a", "add", "lab-pkg"}, outcome: evaluation.OutcomeAllow},
			{name: "dir-block", args: []string{"-C", "packages/a", "add", "lab-pkg"}, outcome: evaluation.OutcomeBlock, failed: true},
			{name: "recursive-install-block", args: []string{"-r", "install"}, seed: true, outcome: evaluation.OutcomeBlock, failed: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				dir := newPnpmTestProject(t, registry, "")
				writePnpmWorkspace(t, dir, files)
				if test.seed {
					assertPnpmSucceeded(t, runPnpmThroughProxy(t, executable, []string{"--filter", "a", "add", "lab-pkg"}, evaluation.OutcomeAllow))
					for _, modules := range []string{"node_modules", "packages/a/node_modules"} {
						if err := os.RemoveAll(filepath.Join(dir, modules)); err != nil {
							t.Fatal(err)
						}
					}
					usePnpmStore(t, t.TempDir())
					t.Setenv("XDG_CACHE_HOME", t.TempDir())
				}
				before := registry.TarballHits.Load()
				run := runPnpmThroughProxy(t, executable, test.args, test.outcome)
				if test.failed {
					assertPnpmFailed(t, run)
					if hits := registry.TarballHits.Load() - before; hits != 0 || run.calls != 1 {
						t.Fatalf("tarball downloads=%d evaluations=%d, want the tarball evaluated and blocked", hits, run.calls)
					}
				} else {
					assertPnpmSucceeded(t, run)
					if run.calls != 1 {
						t.Fatalf("evaluations = %d, want 1", run.calls)
					}
					if _, err := os.Stat(filepath.Join(dir, "packages", "a", "node_modules", "lab-pkg", "package.json")); err != nil {
						t.Fatalf("package not installed in the member: %v", err)
					}
				}
				if after, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml")); err != nil || string(after) != files["pnpm-workspace.yaml"] {
					t.Fatalf("pnpm-workspace.yaml changed: %q (error %v)", after, err)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// lab-pkg has no binary, so dlx fails after its download, which is what SCFW
// must evaluate.
func TestPnpmDlxEndToEnd(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		pnpx := filepath.Join(filepath.Dir(executable), "pnpx"+filepath.Ext(executable))
		for _, test := range []struct {
			name, executable, invoked string
			args                      []string
		}{
			{"dlx", executable, "pnpm", []string{"dlx", "lab-pkg"}},
			{"pnpx", pnpx, "pnpx", []string{"lab-pkg"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				if _, err := os.Stat(test.executable); err != nil {
					t.Skip("this release has no " + test.invoked + " entry point")
				}
				registry := startNpmRegistry(t)
				newPnpmTestProject(t, registry, "")
				run := runPnpmNamedThroughProxy(t, test.invoked, test.executable, test.args, evaluation.OutcomeBlock)
				assertPnpmFailed(t, run)
				if run.calls != 1 || registry.TarballHits.Load() != 0 {
					t.Fatalf("evaluations=%d tarball downloads=%d, want the dlx download evaluated and blocked", run.calls, registry.TarballHits.Load())
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// Packages already in pnpm's store are linked without a download, so SCFW
// never sees them; this documents that limitation.
func TestPnpmWarmStoreIsNotEvaluated(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		// Fixtures are read relative to the package directory.
		packageDir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		registry := startNpmRegistry(t)
		newPnpmTestProject(t, registry, "")
		assertPnpmSucceeded(t, runPnpmThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow))
		store := os.Getenv("pnpm_config_store_dir")
		t.Chdir(packageDir)
		dir := newPnpmTestProject(t, registry, "")
		usePnpmStore(t, store)
		before := registry.TarballHits.Load()
		run := runPnpmThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeBlock)
		assertPnpmSucceeded(t, run)
		if hits := registry.TarballHits.Load() - before; hits != 0 || run.calls != 0 {
			t.Fatalf("tarball downloads=%d evaluations=%d, want neither for a stored package", hits, run.calls)
		}
		if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
			t.Fatalf("package not linked from the store: %v", err)
		}
	})
}

// A project pinned to another pnpm makes pnpm download that release on start,
// which SCFW must evaluate like any other package.
func TestPnpmPinHandOff(t *testing.T) {
	installed, pinned := os.Getenv("SCFW_TEST_PNPM_11"), os.Getenv("SCFW_TEST_PNPM_12")
	if installed == "" || pinned == "" {
		t.Skip("SCFW_TEST_PNPM_11 and SCFW_TEST_PNPM_12 required for the version pin test")
	}
	output, err := exec.Command(pinned, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	registry := startNpmRegistry(t)
	dir := newPnpmTestProject(t, registry, "")
	writePnpmFile(t, filepath.Join(dir, "package.json"), `{"name":"pinned","private":true,"packageManager":"pnpm@`+strings.TrimSpace(string(output))+`"}`)
	run := runPnpmThroughProxy(t, installed, []string{"add", "lab-pkg"}, evaluation.OutcomeBlock)
	assertPnpmFailed(t, run)
	if run.calls < 1 || registry.TarballHits.Load() != 0 {
		t.Fatalf("evaluations=%d tarball downloads=%d, want the pinned pnpm download evaluated and blocked", run.calls, registry.TarballHits.Load())
	}
	assertProxyCleaned(t, run.config)
}

// Scripts run directly, without the proxy or its environment.
func TestPnpmDirectCommands(t *testing.T) {
	scripts := readProxyFixture(t, "pnpm/scripts/package.json")
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		registry := startNpmRegistry(t)
		dir := newPnpmTestProject(t, registry, "")
		writePnpmFile(t, filepath.Join(dir, "package.json"), scripts)
		manager, err := pnpm.NewPnpm(context.Background(), "pnpm", executable)
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range [][]string{{"run", "hello"}, {"hello"}, {"--help"}} {
			if manager.ProxyCommandSupported(command) {
				t.Fatalf("%q must run directly", command)
			}
		}
		if err := manager.RunCommand(context.Background(), []string{"run", "hello"}); err != nil {
			t.Fatal(err)
		}
		if output, err := os.ReadFile(filepath.Join(dir, "hello.txt")); err != nil || string(output) != "direct" {
			t.Fatalf("script saw HTTPS_PROXY %q (error %v), want no proxy", output, err)
		}
	})
}

func TestPnpmRefusedSettingNeverStarts(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, _ int, executable string) {
		registry := startNpmRegistry(t)
		newPnpmTestProject(t, registry, "local-address=127.0.0.1\n")
		run := runPnpmThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
		if run.setupErr == nil || !strings.Contains(run.setupErr.Error(), "local-address") {
			t.Fatalf("setup error = %v, want the local-address refusal", run.setupErr)
		}
		if run.commandErr != nil || run.calls != 0 || registry.TarballHits.Load() != 0 {
			t.Fatalf("pnpm must not start: command %v, evaluations %d, downloads %d", run.commandErr, run.calls, registry.TarballHits.Load())
		}
	})
}
