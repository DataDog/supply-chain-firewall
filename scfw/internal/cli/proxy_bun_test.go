// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/bun"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// forEachBun runs test against every real Bun release named by
// SCFW_TEST_BUN_1_<minor>; CI pins 1.2.0, 1.3.14, and 1.4.4.
func forEachBun(t *testing.T, test func(t *testing.T, minor int, executable string)) {
	t.Helper()
	for _, minor := range []int{2, 3, 4} {
		t.Run(fmt.Sprintf("bun1.%d", minor), func(t *testing.T) {
			variable := fmt.Sprintf("SCFW_TEST_BUN_1_%d", minor)
			executable := os.Getenv(variable)
			if executable == "" {
				t.Skip(variable + " required for bun integration tests")
			}
			test(t, minor, executable)
		})
	}
}

// newBunTestProject isolates Bun from the host and enters a project whose
// .npmrc selects the test registry. Bun trusts only SCFW's CA; SCFW trusts the
// registry through the user's NODE_EXTRA_CA_CERTS.
func newBunTestProject(t *testing.T, registry *npmTestRegistry, npmrcExtra string) string {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(key, "BUN_") || strings.HasSuffix(lower, "_proxy") ||
			strings.HasPrefix(key, "XDG_") || slices.Contains([]string{"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "NODE_TLS_REJECT_UNAUTHORIZED", "CI"}, key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	for key, value := range map[string]string{
		"HOME": filepath.Join(root, "home"), "XDG_CONFIG_HOME": filepath.Join(root, "config"),
		"XDG_CACHE_HOME": filepath.Join(root, "cache"), "BUN_INSTALL_CACHE_DIR": filepath.Join(root, "bun-cache"),
		"BUN_INSTALL": filepath.Join(root, "bun-install"), "NODE_EXTRA_CA_CERTS": registry.CAPath, "DO_NOT_TRACK": "1",
	} {
		t.Setenv(key, value)
	}
	if err := os.MkdirAll(filepath.Join(root, "home"), 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "project")
	writeNpmProject(t, dir, readProxyFixture(t, "npm/project/package.json"), "registry="+registry.URL+"/\n"+npmrcExtra)
	t.Chdir(dir)
	return dir
}

type capturingBunRunner struct {
	bun.Bun
	capture func(proxy.ClientConfig)
}

func (r capturingBunRunner) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	r.capture(config)
	return r.Bun.ProxyCommand(ctx, args, config)
}

type bunProxyRun struct {
	commandErr, setupErr error
	calls                int32
	details              string
	config               proxy.ClientConfig
}

func runBunThroughProxy(t *testing.T, name, executable string, args []string, outcome evaluation.Outcome) bunProxyRun {
	t.Helper()
	manager, err := bun.NewBun(context.Background(), name, executable)
	if err != nil {
		t.Fatal(err)
	}
	var run bunProxyRun
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
		packageEvaluator := newProxyPackageEvaluator(ctx, time.Now(), append([]string{name}, args...), name, manager.Executable(), "", evaluator, nopReporter{}, &details)
		hook, err := newNpmProxyHook(ctx, manager, args, client, packageEvaluator.evaluatePackage)
		return []proxy.RequestHook{hook}, err
	}
	runner := capturingBunRunner{Bun: manager, capture: func(config proxy.ClientConfig) { run.config = config }}
	run.commandErr, run.setupErr = runThroughProxy(context.Background(), runner, args, configure)
	run.calls, run.details = calls.Load(), details.String()
	return run
}

func assertBunSucceeded(t *testing.T, run bunProxyRun) {
	t.Helper()
	if run.setupErr != nil || run.commandErr != nil {
		t.Fatalf("bun failed: setup %v, command %v", run.setupErr, run.commandErr)
	}
}

func assertBunFailed(t *testing.T, run bunProxyRun) {
	t.Helper()
	if run.setupErr != nil {
		t.Fatalf("setup error = %v, want bun to run and fail", run.setupErr)
	}
	assertNpmFailed(t, run.commandErr)
}

func writeBunFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// seedBunLockfile installs lab-pkg once, then leaves only the manifest and
// lockfile, with an empty cache, so the next command downloads it again.
func seedBunLockfile(t *testing.T, executable, dir string) {
	t.Helper()
	assertBunSucceeded(t, runBunThroughProxy(t, "bun", executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow))
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUN_INSTALL_CACHE_DIR", t.TempDir())
}

func readBunLockfile(dir string) []byte {
	for _, name := range []string{"bun.lock", "bun.lockb"} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			return data
		}
	}
	return nil
}

func TestBunProxyEndToEnd(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
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
			{name: "bun-failure", args: []string{"add", "does-not-exist"}, outcome: evaluation.OutcomeAllow, failed: true},
			{name: "options-before-command", args: []string{"--cwd=.", "--silent", "add", "lab-pkg"},
				outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
			{name: "install-allow", args: []string{"install"}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
			{name: "frozen-lockfile-block", args: []string{"install", "--frozen-lockfile"}, seed: true,
				outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				dir := newBunTestProject(t, registry, "")
				if test.seed {
					seedBunLockfile(t, executable, dir)
				}
				manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
				if err != nil {
					t.Fatal(err)
				}
				lockfile := readBunLockfile(dir)
				before := registry.TarballHits.Load()
				run := runBunThroughProxy(t, "bun", executable, test.args, test.outcome)
				if test.failed {
					assertBunFailed(t, run)
				} else {
					assertBunSucceeded(t, run)
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
				if test.seed && !bytes.Equal(readBunLockfile(dir), lockfile) {
					t.Fatal("the lockfile changed")
				}
				if test.failed {
					if after, err := os.ReadFile(filepath.Join(dir, "package.json")); err != nil || !bytes.Equal(after, manifest) {
						t.Fatal("a failed command changed package.json")
					}
					if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "index.js")); err == nil {
						t.Fatal("a blocked package was installed")
					}
				} else if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
					t.Fatalf("package not installed: %v", err)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// bunx and bun x download the package they run; lab-pkg has no binary, so
// they fail after the download, which is what SCFW must evaluate.
func TestBunxEndToEnd(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		bunx := filepath.Join(t.TempDir(), "bunx")
		if err := os.Symlink(executable, bunx); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name, invoked, executable string
			args                      []string
		}{
			{"bun x", "bun", executable, []string{"x", "lab-pkg"}},
			{"bunx", "bunx", bunx, []string{"lab-pkg"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				newBunTestProject(t, registry, "")
				// bunx does not read the project's .npmrc.
				t.Setenv("NPM_CONFIG_REGISTRY", registry.URL+"/")
				run := runBunThroughProxy(t, test.invoked, test.executable, test.args, evaluation.OutcomeBlock)
				assertBunFailed(t, run)
				if run.calls != 1 || registry.TarballHits.Load() != 0 {
					t.Fatalf("evaluations=%d tarball downloads=%d, want the download evaluated and blocked", run.calls, registry.TarballHits.Load())
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// Bun installs a missing import when a script runs outside a project with
// node_modules, which SCFW must evaluate.
func TestBunRunAutoInstall(t *testing.T) {
	script := readProxyFixture(t, "bun/import.js")
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		for _, test := range []struct {
			name    string
			args    []string
			outcome evaluation.Outcome
			failed  bool
		}{
			{"run-allow", []string{"run", "import.js"}, evaluation.OutcomeAllow, false},
			{"run-block", []string{"run", "import.js"}, evaluation.OutcomeBlock, true},
			{"file-block", []string{"import.js"}, evaluation.OutcomeBlock, true},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				dir := newBunTestProject(t, registry, "")
				// Auto-install only runs without a package.json.
				if err := os.Remove(filepath.Join(dir, "package.json")); err != nil {
					t.Fatal(err)
				}
				writeBunFile(t, filepath.Join(dir, "import.js"), script)
				run := runBunThroughProxy(t, "bun", executable, test.args, test.outcome)
				if test.failed {
					assertBunFailed(t, run)
				} else {
					assertBunSucceeded(t, run)
				}
				if run.calls != 1 {
					t.Fatalf("evaluations = %d, want 1", run.calls)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

func TestBunPreservesExitStatus(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		script := readProxyFixture(t, "bun/fail.js")
		registry := startNpmRegistry(t)
		dir := newBunTestProject(t, registry, "")
		writeBunFile(t, filepath.Join(dir, "fail.js"), script)
		run := runBunThroughProxy(t, "bun", executable, []string{"run", "fail.js"}, evaluation.OutcomeAllow)
		var exitErr *exec.ExitError
		if run.setupErr != nil || !errors.As(run.commandErr, &exitErr) || exitErr.ExitCode() != 7 {
			t.Fatalf("setup %v, command %v, want exit status 7", run.setupErr, run.commandErr)
		}
	})
}

// A script's own HTTPS requests pass through SCFW unevaluated.
func TestBunScriptFetchPassesThrough(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		script := readProxyFixture(t, "bun/fetch.js")
		registry := startNpmRegistry(t)
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = w.Write([]byte("hello"))
		}))
		t.Cleanup(server.Close)
		dir := newBunTestProject(t, registry, "")
		// SCFW trusts the server through the user's extra CAs.
		caPath := filepath.Join(t.TempDir(), "ca.pem")
		writeBunFile(t, caPath, registry.CAPEM+"\n"+string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
		t.Setenv("NODE_EXTRA_CA_CERTS", caPath)
		writeBunFile(t, filepath.Join(dir, "fetch.js"), script)
		run := runBunThroughProxy(t, "bun", executable, []string{"run", "fetch.js", server.URL}, evaluation.OutcomeBlock)
		assertBunSucceeded(t, run)
		if requests.Load() != 1 || run.calls != 0 {
			t.Fatalf("requests=%d evaluations=%d, want one unevaluated request", requests.Load(), run.calls)
		}
	})
}

// Every way a user can point Bun elsewhere must still leave the tarball
// download evaluated and blocked, without changing Bun's configuration files.
func TestBunBypassAttemptsAreStillEvaluated(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		for _, test := range []struct {
			name           string
			npmrc          func(tunnel string) string
			bunfig, dotenv func(tunnel string) string
		}{
			{name: "npmrc https-proxy", npmrc: func(tunnel string) string { return "https-proxy=" + tunnel + "\n" }},
			{name: "npmrc noproxy", npmrc: func(string) string { return "noproxy=localhost\n" }},
			{name: "bunfig proxy", bunfig: func(tunnel string) string { return "[install]\nproxy = \"" + tunnel + "\"\n" }},
			{name: "bunfig cafile", bunfig: func(string) string { return "[install]\ncafile = \"" + os.Getenv("NODE_EXTRA_CA_CERTS") + "\"\n" }},
			{name: "dotenv NO_PROXY", dotenv: func(string) string { return "NO_PROXY=localhost\nno_proxy=localhost\n" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				var hits atomic.Int32
				upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &hits})
				tunnel := strings.Replace(upstream.URL, "://", "://proxy:secret@", 1)
				extra := ""
				if test.npmrc != nil {
					extra = test.npmrc(tunnel)
				}
				dir := newBunTestProject(t, registry, extra)
				files := map[string]func(string) string{"bunfig.toml": test.bunfig, ".env": test.dotenv}
				contents := map[string][]byte{}
				for name, content := range files {
					if content != nil {
						writeBunFile(t, filepath.Join(dir, name), content(tunnel))
					}
				}
				for _, name := range []string{".npmrc", "bunfig.toml", ".env"} {
					contents[name], _ = os.ReadFile(filepath.Join(dir, name))
				}
				run := runBunThroughProxy(t, "bun", executable, []string{"add", "lab-pkg"}, evaluation.OutcomeBlock)
				assertBunFailed(t, run)
				if run.calls != 1 || registry.TarballHits.Load() != 0 {
					t.Fatalf("evaluations=%d tarball downloads=%d, want the tarball evaluated and blocked", run.calls, registry.TarballHits.Load())
				}
				for name, before := range contents {
					if after, _ := os.ReadFile(filepath.Join(dir, name)); !bytes.Equal(after, before) {
						t.Fatalf("%s changed", name)
					}
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

func TestBunChainsToAuthenticatedUpstream(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		registry := startNpmRegistry(t)
		var tunnels atomic.Int32
		tunnel := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
		newBunTestProject(t, registry, "")
		t.Setenv("HTTPS_PROXY", strings.Replace(tunnel.URL, "://", "://proxy:secret@", 1))
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(previous) })

		run := runBunThroughProxy(t, "bun", executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
		assertBunSucceeded(t, run)
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

func TestBunWithoutUpstreamConnectsDirectly(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		registry := startNpmRegistry(t)
		var tunnels atomic.Int32
		proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
		newBunTestProject(t, registry, "")
		run := runBunThroughProxy(t, "bun", executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
		assertBunSucceeded(t, run)
		if tunnels.Load() != 0 || registry.TarballHits.Load() != 1 {
			t.Fatalf("tunnels=%d tarball downloads=%d, want a direct download", tunnels.Load(), registry.TarballHits.Load())
		}
	})
}

// Packages already in Bun's cache are linked without a download, so SCFW
// never sees them; this documents that limitation.
func TestBunWarmCacheIsNotEvaluated(t *testing.T) {
	forEachBun(t, func(t *testing.T, _ int, executable string) {
		packageDir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		registry := startNpmRegistry(t)
		newBunTestProject(t, registry, "")
		assertBunSucceeded(t, runBunThroughProxy(t, "bun", executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow))
		cache := os.Getenv("BUN_INSTALL_CACHE_DIR")
		t.Chdir(packageDir)
		dir := newBunTestProject(t, registry, "")
		t.Setenv("BUN_INSTALL_CACHE_DIR", cache)
		before := registry.TarballHits.Load()
		run := runBunThroughProxy(t, "bun", executable, []string{"add", "lab-pkg"}, evaluation.OutcomeBlock)
		assertBunSucceeded(t, run)
		if hits := registry.TarballHits.Load() - before; hits != 0 || run.calls != 0 {
			t.Fatalf("tarball downloads=%d evaluations=%d, want neither for a cached package", hits, run.calls)
		}
		if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
			t.Fatalf("package not linked from the cache: %v", err)
		}
	})
}
