// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"log/slog"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/yarn"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// yarnTestExecutable returns a real Yarn release named by variable; CI pins
// Yarn 1.22.22 and 4.18.1 in SCFW_TEST_YARN_CLASSIC and SCFW_TEST_YARN_BERRY.
func yarnTestExecutable(t *testing.T, variable string) string {
	t.Helper()
	executable := os.Getenv(variable)
	if executable == "" {
		t.Skip(variable + " required for Yarn integration tests")
	}
	return executable
}

// newYarnTestProject isolates Yarn from the host and enters a project whose rc
// file selects the test registry and trusts its certificate.
func newYarnTestProject(t *testing.T, rcName, rc string) string {
	t.Helper()
	project := readProxyFixture(t, "npm/project/package.json")
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(lower, "yarn_") || strings.HasSuffix(lower, "_proxy") ||
			lower == "proxy" || slices.Contains([]string{"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "PREFIX", "DESTDIR", "NODE_OPTIONS", "COREPACK_ENABLE_STRICT"}, key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("PREFIX", filepath.Join(root, "prefix"))
	t.Setenv("YARN_CACHE_FOLDER", filepath.Join(root, "cache"))
	t.Setenv("YARN_GLOBAL_FOLDER", filepath.Join(root, "global"))
	t.Setenv("YARN_ENABLE_TELEMETRY", "0")
	dir := filepath.Join(root, "project")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"package.json": project, rcName: rc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	return dir
}

func classicYarnrc(registry *npmTestRegistry, extra string) string {
	return `registry "` + registry.URL + `/"` + "\n" + `cafile "` + registry.CAPath + `"` + "\n" +
		"disable-self-update-check true\n" + extra
}

type capturingYarnRunner struct {
	yarn.Yarn
	capture func(proxy.ClientConfig)
}

func (r capturingYarnRunner) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	r.capture(config)
	return r.Yarn.ProxyCommand(ctx, args, config)
}

type yarnProxyRun struct {
	commandErr, setupErr error
	calls                int32
	details              string
	config               proxy.ClientConfig
}

func runYarnThroughProxy(t *testing.T, executable string, args []string, outcome evaluation.Outcome) yarnProxyRun {
	t.Helper()
	manager, err := yarn.NewYarn(context.Background(), "yarn", executable)
	if err != nil {
		t.Fatal(err)
	}
	var run yarnProxyRun
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
		packageEvaluator := newProxyPackageEvaluator(ctx, time.Now(), append([]string{"yarn"}, args...), "yarn", manager.Executable(), "", evaluator, nopReporter{}, &details)
		hook, err := newNpmProxyHook(ctx, manager, args, client, packageEvaluator.evaluatePackage)
		return []proxy.RequestHook{hook}, err
	}
	runner := capturingYarnRunner{Yarn: manager, capture: func(config proxy.ClientConfig) { run.config = config }}
	run.commandErr, run.setupErr = runThroughProxy(context.Background(), runner, args, configure)
	run.calls, run.details = calls.Load(), details.String()
	return run
}

func assertYarnSucceeded(t *testing.T, run yarnProxyRun) {
	t.Helper()
	if run.setupErr != nil || run.commandErr != nil {
		t.Fatalf("yarn failed: setup %v, command %v", run.setupErr, run.commandErr)
	}
}

func assertYarnFailed(t *testing.T, run yarnProxyRun) {
	t.Helper()
	if run.setupErr != nil {
		t.Fatalf("setup error = %v, want Yarn to run and fail", run.setupErr)
	}
	assertNpmFailed(t, run.commandErr)
}

// seedYarnLockfile installs lab-pkg once, then leaves only the manifest and
// lockfile, with an empty cache, so the next command downloads it again.
// Yarn 4 also mirrors archives in its global folder.
func seedYarnLockfile(t *testing.T, executable, dir string) {
	t.Helper()
	assertYarnSucceeded(t, runYarnThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow))
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YARN_CACHE_FOLDER", t.TempDir())
	t.Setenv("YARN_GLOBAL_FOLDER", t.TempDir())
}

func TestYarnClassicProxyEndToEnd(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_CLASSIC")
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
		{name: "yarn-failure", args: []string{"add", "does-not-exist"}, outcome: evaluation.OutcomeAllow, failed: true},
		{name: "frozen-lockfile-block", args: []string{"install", "--frozen-lockfile"}, seed: true,
			outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		{name: "bare-install-allow", args: []string{}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "upgrade-allow", args: []string{"upgrade"}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "options-before-command", args: []string{"--cwd", ".", "--non-interactive", "add", "lab-pkg"},
			outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := startNpmRegistry(t)
			rc := classicYarnrc(registry, "")
			dir := newYarnTestProject(t, ".yarnrc", rc)
			if test.seed {
				seedYarnLockfile(t, executable, dir)
			}
			manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
			if err != nil {
				t.Fatal(err)
			}
			before := registry.TarballHits.Load()
			run := runYarnThroughProxy(t, executable, test.args, test.outcome)
			if test.failed {
				assertYarnFailed(t, run)
			} else {
				assertYarnSucceeded(t, run)
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
			if test.failed && !test.seed {
				if after, err := os.ReadFile(filepath.Join(dir, "package.json")); err != nil || !bytes.Equal(after, manifest) {
					t.Fatalf("package.json changed by a failed command: %q (error %v)", after, err)
				}
			}
			if !test.failed {
				if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
					t.Fatalf("package not installed: %v", err)
				}
				if entries, err := os.ReadDir(os.Getenv("YARN_CACHE_FOLDER")); err != nil || len(entries) == 0 {
					t.Fatalf("yarn did not use its configured cache: %v", err)
				}
			}
			if after, err := os.ReadFile(filepath.Join(dir, ".yarnrc")); err != nil || string(after) != rc {
				t.Fatalf(".yarnrc changed: %q (error %v)", after, err)
			}
			assertProxyCleaned(t, run.config)
		})
	}
}

func TestYarnClassicBypassAttemptsAreStillEvaluated(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_CLASSIC")
	for _, test := range []struct {
		name   string
		yarnrc func(tunnel string) string
		env    func(tunnel string) [2]string
		args   func(tunnel string) []string
	}{
		{name: "yarnrc https-proxy", yarnrc: func(tunnel string) string { return `https-proxy "` + tunnel + `"` + "\n" }},
		{name: "yarnrc rc-arg https-proxy", yarnrc: func(tunnel string) string { return `--https-proxy "` + tunnel + `"` + "\n" }},
		{name: "yarnrc https-proxy false", yarnrc: func(string) string { return "https-proxy false\nproxy false\n" }},
		{name: "env YARN_HTTPS_PROXY", env: func(tunnel string) [2]string { return [2]string{"YARN_HTTPS_PROXY", tunnel} }},
		{name: "env npm_config_https_proxy", env: func(tunnel string) [2]string { return [2]string{"npm_config_https_proxy", tunnel} }},
		{name: "env NO_PROXY", env: func(string) [2]string { return [2]string{"NO_PROXY", "localhost"} }},
		{name: "option https-proxy", args: func(tunnel string) []string { return []string{"--https-proxy=" + tunnel} }},
		{name: "option proxy space form", args: func(tunnel string) []string { return []string{"--proxy", tunnel} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := startNpmRegistry(t)
			var hits atomic.Int32
			upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &hits})
			tunnel := strings.Replace(upstream.URL, "://", "://proxy:secret@", 1)
			extra := ""
			if test.yarnrc != nil {
				extra = test.yarnrc(tunnel)
			}
			newYarnTestProject(t, ".yarnrc", classicYarnrc(registry, extra))
			if test.env != nil {
				pair := test.env(tunnel)
				t.Setenv(pair[0], pair[1])
			}
			args := []string{"add", "lab-pkg"}
			if test.args != nil {
				args = append(args, test.args(tunnel)...)
			}
			run := runYarnThroughProxy(t, executable, args, evaluation.OutcomeBlock)
			assertYarnFailed(t, run)
			if run.calls != 1 || registry.TarballHits.Load() != 0 {
				t.Fatalf("evaluations=%d tarball downloads=%d, want the tarball evaluated and blocked", run.calls, registry.TarballHits.Load())
			}
			assertProxyCleaned(t, run.config)
		})
	}
}

func TestYarnClassicChainsToAuthenticatedUpstream(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_CLASSIC")
	registry := startNpmRegistry(t)
	var tunnels atomic.Int32
	tunnel := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
	upstream := strings.Replace(tunnel.URL, "://", "://proxy:secret@", 1)
	newYarnTestProject(t, ".yarnrc", classicYarnrc(registry, `https-proxy "`+upstream+`"`+"\n"))
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	run := runYarnThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
	assertYarnSucceeded(t, run)
	if tunnels.Load() < 1 || registry.TarballHits.Load() != 1 || run.calls != 1 {
		t.Fatalf("tunnels=%d tarball downloads=%d evaluations=%d", tunnels.Load(), registry.TarballHits.Load(), run.calls)
	}
	for _, output := range []string{logs.String(), run.details} {
		if strings.Contains(output, "secret") {
			t.Fatalf("upstream credential leaked: %s", output)
		}
	}
	assertProxyCleaned(t, run.config)
}

func TestYarnClassicWithoutUpstreamConnectsDirectly(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_CLASSIC")
	registry := startNpmRegistry(t)
	var tunnels atomic.Int32
	proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
	newYarnTestProject(t, ".yarnrc", classicYarnrc(registry, ""))
	run := runYarnThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
	assertYarnSucceeded(t, run)
	if tunnels.Load() != 0 || registry.TarballHits.Load() != 1 {
		t.Fatalf("tunnels=%d tarball downloads=%d, want a direct download", tunnels.Load(), registry.TarballHits.Load())
	}
}

func berryYarnrc(registry *npmTestRegistry, extra string) string {
	return `npmRegistryServer: "` + registry.URL + `"` + "\n" + `httpsCaFilePath: "` + registry.CAPath + `"` + "\n" +
		"enableTelemetry: false\nenableGlobalCache: false\n" + extra
}

// newBerryTestProject also disables the immutable installs Yarn 4 enables on CI.
func newBerryTestProject(t *testing.T, rc string) string {
	t.Helper()
	dir := newYarnTestProject(t, ".yarnrc.yml", rc)
	t.Setenv("YARN_ENABLE_IMMUTABLE_INSTALLS", "false")
	return dir
}

func TestYarnBerryProxyEndToEnd(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
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
		{name: "yarn-failure", args: []string{"add", "does-not-exist"}, outcome: evaluation.OutcomeAllow, failed: true},
		{name: "immutable-block", args: []string{"install", "--immutable"}, seed: true,
			outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		{name: "bare-install-allow", args: []string{}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "up-allow", args: []string{"up", "lab-pkg"}, seed: true, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := startNpmRegistry(t)
			rc := berryYarnrc(registry, "nodeLinker: node-modules\n")
			dir := newBerryTestProject(t, rc)
			if test.seed {
				seedYarnLockfile(t, executable, dir)
			}
			manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
			if err != nil {
				t.Fatal(err)
			}
			lockfile, lockErr := os.ReadFile(filepath.Join(dir, "yarn.lock"))
			before := registry.TarballHits.Load()
			run := runYarnThroughProxy(t, executable, test.args, test.outcome)
			if test.failed {
				assertYarnFailed(t, run)
			} else {
				assertYarnSucceeded(t, run)
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
				afterLock, afterLockErr := os.ReadFile(filepath.Join(dir, "yarn.lock"))
				if err != nil || !bytes.Equal(after, manifest) || (afterLockErr == nil) != (lockErr == nil) || !bytes.Equal(afterLock, lockfile) {
					t.Fatalf("a failed command changed package.json or yarn.lock")
				}
			} else if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
				t.Fatalf("package not installed: %v", err)
			}
			if after, err := os.ReadFile(filepath.Join(dir, ".yarnrc.yml")); err != nil || string(after) != rc {
				t.Fatalf(".yarnrc.yml changed: %q (error %v)", after, err)
			}
			assertProxyCleaned(t, run.config)
		})
	}
}

func TestYarnBerryPnPInstall(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	registry := startNpmRegistry(t)
	dir := newBerryTestProject(t, berryYarnrc(registry, ""))
	run := runYarnThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
	assertYarnSucceeded(t, run)
	if _, err := os.Stat(filepath.Join(dir, ".pnp.cjs")); err != nil || run.calls != 1 {
		t.Fatalf("Plug'n'Play install missing (evaluations %d): %v", run.calls, err)
	}
}

func TestYarnBerryRefusesNetworkSettings(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	registry := startNpmRegistry(t)
	newBerryTestProject(t, berryYarnrc(registry, "networkSettings:\n  \"*\":\n    httpsProxy: \"http://127.0.0.1:9\"\n"))
	run := runYarnThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
	if run.setupErr == nil || !strings.Contains(run.setupErr.Error(), "networkSettings") {
		t.Fatalf("setup error = %v, want the networkSettings refusal", run.setupErr)
	}
	if run.commandErr != nil || run.calls != 0 || registry.TarballHits.Load() != 0 {
		t.Fatalf("Yarn must not start: command %v, evaluations %d, downloads %d", run.commandErr, run.calls, registry.TarballHits.Load())
	}
}

func TestYarnBerryChainsToAuthenticatedUpstream(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	registry := startNpmRegistry(t)
	var tunnels atomic.Int32
	tunnel := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
	newBerryTestProject(t, berryYarnrc(registry, "nodeLinker: node-modules\n"))
	t.Setenv("YARN_HTTPS_PROXY", strings.Replace(tunnel.URL, "://", "://proxy:secret@", 1))
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	run := runYarnThroughProxy(t, executable, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
	assertYarnSucceeded(t, run)
	if tunnels.Load() < 1 || registry.TarballHits.Load() != 1 || run.calls != 1 {
		t.Fatalf("tunnels=%d tarball downloads=%d evaluations=%d", tunnels.Load(), registry.TarballHits.Load(), run.calls)
	}
	for _, output := range []string{logs.String(), run.details} {
		if strings.Contains(output, "secret") {
			t.Fatalf("upstream credential leaked: %s", output)
		}
	}
	assertProxyCleaned(t, run.config)
}

// A global Yarn Classic hands off to the project's checked-in Yarn 4 release.
func TestYarnClassicHandsOffToBerryYarnPath(t *testing.T) {
	classic := yarnTestExecutable(t, "SCFW_TEST_YARN_CLASSIC")
	berry := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	release, err := os.ReadFile(berry)
	if err != nil {
		t.Fatal(err)
	}
	registry := startNpmRegistry(t)
	dir := newBerryTestProject(t, berryYarnrc(registry, "nodeLinker: node-modules\nyarnPath: .yarn/releases/yarn-4.18.1.cjs\n"))
	if err := os.MkdirAll(filepath.Join(dir, ".yarn", "releases"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".yarn", "releases", "yarn-4.18.1.cjs"), release, 0700); err != nil {
		t.Fatal(err)
	}
	run := runYarnThroughProxy(t, classic, []string{"add", "lab-pkg"}, evaluation.OutcomeAllow)
	assertYarnSucceeded(t, run)
	if registry.TarballHits.Load() != 1 || run.calls != 1 {
		t.Fatalf("tarball downloads=%d evaluations=%d", registry.TarballHits.Load(), run.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
		t.Fatalf("package not installed: %v", err)
	}
}
