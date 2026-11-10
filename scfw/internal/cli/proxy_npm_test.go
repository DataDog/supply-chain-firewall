// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// npmTestRegistry serves lab-pkg@1.0.0 over TLS with its own certificate.
type npmTestRegistry struct {
	URL, CAPath, CAPEM string
	TarballHits        atomic.Int32
}

func npmTarball(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressed)
	for _, name := range []string{"package.json", "index.js"} {
		body := readProxyFixture(t, filepath.Join("npm", "package", name))
		header := &tar.Header{Name: "package/" + name, Mode: 0644, Size: int64(len(body)), ModTime: time.Unix(1700000000, 0)}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func startNpmRegistry(t *testing.T) *npmTestRegistry {
	t.Helper()
	tarball := npmTarball(t)
	digest := sha512.Sum512(tarball)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
	packument := readProxyFixture(t, "npm/packument.json.tmpl")
	registry := &npmTestRegistry{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lab-pkg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, packument, registry.URL+"/lab-pkg/-/lab-pkg-1.0.0.tgz", integrity)
		case "/lab-pkg/-/lab-pkg-1.0.0.tgz":
			registry.TarballHits.Add(1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(tarball)
		default:
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
		}
	}))
	// npm verifies an IP-literal registry reached through a proxy against
	// "localhost" (https-proxy-agent omits the servername), so the registry is
	// named localhost and carries its own certificate for that name.
	certificate, caPEM, _ := proxyTLSIdentity(t)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	registry.URL = "https://localhost:" + server.URL[strings.LastIndex(server.URL, ":")+1:]
	registry.CAPEM = string(caPEM)
	registry.CAPath = filepath.Join(t.TempDir(), "registry-ca.pem")
	if err := os.WriteFile(registry.CAPath, []byte(registry.CAPEM), 0600); err != nil {
		t.Fatal(err)
	}
	return registry
}

// newNpmTestProject isolates npm from the host and enters a project whose
// .npmrc selects the test registry and trusts its certificate.
func newNpmTestProject(t *testing.T, registry *npmTestRegistry, npmrcExtra string) string {
	t.Helper()
	project := readProxyFixture(t, "npm/project/package.json")
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasSuffix(lower, "_proxy") || lower == "proxy" ||
			slices.Contains([]string{"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "PREFIX", "DESTDIR", "NODE_OPTIONS"}, key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("PREFIX", filepath.Join(root, "prefix"))
	t.Setenv("npm_config_cache", filepath.Join(root, "cache"))
	for key, value := range map[string]string{
		"npm_config_update_notifier": "false", "npm_config_audit": "false",
		"npm_config_fund": "false", "npm_config_fetch_retries": "0",
	} {
		t.Setenv(key, value)
	}
	dir := filepath.Join(root, "project")
	writeNpmProject(t, dir, project, "registry="+registry.URL+"/\ncafile="+registry.CAPath+"\n"+npmrcExtra)
	t.Chdir(dir)
	return dir
}

func writeNpmProject(t *testing.T, dir, packageJSON, npmrc string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"package.json": packageJSON, ".npmrc": npmrc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

type capturingNpmRunner struct {
	npm.Npm
	capture func(proxy.ClientConfig)
}

func (r capturingNpmRunner) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	r.capture(config)
	return r.Npm.ProxyCommand(ctx, args, config)
}

type npmProxyRun struct {
	commandErr error
	calls      int32
	details    string
	sources    []string
	config     proxy.ClientConfig
}

func runNpmThroughProxy(t *testing.T, args []string, outcome evaluation.Outcome) npmProxyRun {
	t.Helper()
	executable, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm required for npm integration tests")
	}
	manager, err := npm.NewNpm(context.Background(), "npm", executable)
	if err != nil {
		t.Fatal(err)
	}
	var run npmProxyRun
	var calls atomic.Int32
	var details bytes.Buffer
	evaluator := proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		calls.Add(1)
		if interactive {
			t.Error("proxy evaluation must not prompt")
		}
		for target := range targets.Items() {
			run.sources = append(run.sources, target.Source)
		}
		return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome}, nil
	})
	configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
		packageEvaluator := newProxyPackageEvaluator(ctx, time.Now(), append([]string{"npm"}, args...), "npm", manager.Executable(), "", evaluator, nopReporter{}, &details)
		hook, err := newNpmProxyHook(ctx, manager, args, client, packageEvaluator.evaluatePackage)
		return []proxy.RequestHook{hook}, err
	}
	runner := capturingNpmRunner{Npm: manager, capture: func(config proxy.ClientConfig) { run.config = config }}
	commandErr, setupErr := runThroughProxy(context.Background(), runner, args, configure)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	run.commandErr, run.calls, run.details = commandErr, calls.Load(), details.String()
	return run
}

func assertNpmFailed(t *testing.T, err error) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("command error = %v, want a non-zero npm exit status", err)
	}
}

func TestNpmProxyEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm required for npm integration tests")
	}
	for _, test := range []struct {
		name    string
		args    func(registry *npmTestRegistry, dir string) []string
		prepare func(t *testing.T, registry *npmTestRegistry, dir string)
		outcome evaluation.Outcome
		// hits is the number of tarball downloads the run itself may make.
		hits, calls int32
		failed      bool
	}{
		{name: "install-allow", outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "install-block", outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		{name: "warn-continues", outcome: evaluation.OutcomeWarn, hits: 1, calls: 1},
		{name: "npm-failure", args: func(*npmTestRegistry, string) []string { return []string{"install", "does-not-exist"} },
			outcome: evaluation.OutcomeAllow, failed: true},
		{name: "add", args: func(*npmTestRegistry, string) []string { return []string{"add", "lab-pkg"} }, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "i", args: func(*npmTestRegistry, string) []string { return []string{"i", "lab-pkg"} }, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "ci-block", args: func(*npmTestRegistry, string) []string { return []string{"ci"} },
			prepare: seedNpmLockfile, outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		{name: "update-allow", args: func(*npmTestRegistry, string) []string { return []string{"update"} },
			prepare: seedNpmLockfile, outcome: evaluation.OutcomeAllow, hits: 1, calls: 1},
		{name: "options-around-command", args: func(*npmTestRegistry, string) []string {
			return []string{"--loglevel=warn", "install", "lab-pkg", "--save-dev"}
		}, outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		{name: "registry-option", args: func(registry *npmTestRegistry, _ string) []string {
			return []string{"install", "lab-pkg", "--registry", registry.URL + "/"}
		}, outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
		{name: "prefix-option", args: func(_ *npmTestRegistry, dir string) []string {
			return []string{"--prefix", filepath.Join(dir, "other"), "install", "lab-pkg"}
		}, prepare: func(t *testing.T, registry *npmTestRegistry, dir string) {
			npmrc, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
			if err != nil {
				t.Fatal(err)
			}
			writeNpmProject(t, filepath.Join(dir, "other"), `{"name":"other","version":"1.0.0","private":true}`, string(npmrc))
		}, outcome: evaluation.OutcomeBlock, calls: 1, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := startNpmRegistry(t)
			dir := newNpmTestProject(t, registry, "")
			if test.prepare != nil {
				test.prepare(t, registry, dir)
			}
			npmrc, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"install", "lab-pkg"}
			if test.args != nil {
				args = test.args(registry, dir)
			}
			before := registry.TarballHits.Load()
			run := runNpmThroughProxy(t, args, test.outcome)
			if test.failed {
				assertNpmFailed(t, run.commandErr)
			} else if run.commandErr != nil {
				t.Fatalf("npm failed: %v", run.commandErr)
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
			if !test.failed {
				if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
					t.Fatalf("package not installed: %v", err)
				}
				if entries, err := os.ReadDir(os.Getenv("npm_config_cache")); err != nil || len(entries) == 0 {
					t.Fatalf("npm did not use its configured cache: %v", err)
				}
			}
			if after, err := os.ReadFile(filepath.Join(dir, ".npmrc")); err != nil || !bytes.Equal(after, npmrc) {
				t.Fatalf(".npmrc changed: %q (error %v)", after, err)
			}
			assertProxyCleaned(t, run.config)
		})
	}
}

// seedNpmLockfile installs lab-pkg once, then leaves only the manifest and
// lockfile, with an empty cache, so the next command downloads it again.
func seedNpmLockfile(t *testing.T, _ *npmTestRegistry, dir string) {
	t.Helper()
	if run := runNpmThroughProxy(t, []string{"install", "lab-pkg"}, evaluation.OutcomeAllow); run.commandErr != nil {
		t.Fatalf("seed install failed: %v", run.commandErr)
	}
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("npm_config_cache", t.TempDir())
}

func TestNpmProxyBypassAttemptsAreStillEvaluated(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm required for npm integration tests")
	}
	for _, test := range []struct {
		name  string
		npmrc func(tunnel string) string
		env   func(registry *npmTestRegistry, tunnel string) [2]string
		args  func(registry *npmTestRegistry, tunnel string) []string
	}{
		{name: "npmrc noproxy", npmrc: func(string) string { return "noproxy=localhost\n" }},
		{name: "npmrc https-proxy", npmrc: func(tunnel string) string { return "https-proxy=" + tunnel + "\n" }},
		{name: "env NO_PROXY", env: func(*npmTestRegistry, string) [2]string { return [2]string{"NO_PROXY", "localhost"} }},
		{name: "env NPM_CONFIG_NOPROXY", env: func(*npmTestRegistry, string) [2]string { return [2]string{"NPM_CONFIG_NOPROXY", "localhost"} }},
		{name: "env dashed https-proxy", env: func(_ *npmTestRegistry, tunnel string) [2]string { return [2]string{"npm_config_https-proxy", tunnel} }},
		{name: "env NPM_CONFIG_CA", env: func(registry *npmTestRegistry, _ string) [2]string { return [2]string{"NPM_CONFIG_CA", registry.CAPEM} }},
		{name: "option noproxy", args: func(*npmTestRegistry, string) []string { return []string{"--noproxy=localhost"} }},
		{name: "option noproxy space form", args: func(*npmTestRegistry, string) []string { return []string{"--noproxy", "localhost"} }},
		{name: "option noproxy abbreviation", args: func(*npmTestRegistry, string) []string { return []string{"--nop=localhost"} }},
		{name: "option https-proxy", args: func(_ *npmTestRegistry, tunnel string) []string { return []string{"--https-proxy=" + tunnel} }},
		{name: "option ca", args: func(registry *npmTestRegistry, _ string) []string { return []string{"--ca=" + registry.CAPEM} }},
		{name: "option cafile", args: func(registry *npmTestRegistry, _ string) []string { return []string{"--cafile=" + registry.CAPath} }},
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
			newNpmTestProject(t, registry, extra)
			if test.env != nil {
				pair := test.env(registry, tunnel)
				t.Setenv(pair[0], pair[1])
			}
			args := []string{"install", "lab-pkg"}
			if test.args != nil {
				args = append(args, test.args(registry, tunnel)...)
			}
			run := runNpmThroughProxy(t, args, evaluation.OutcomeBlock)
			assertNpmFailed(t, run.commandErr)
			if run.calls != 1 || registry.TarballHits.Load() != 0 {
				t.Fatalf("evaluations=%d tarball downloads=%d, want the tarball evaluated and blocked", run.calls, registry.TarballHits.Load())
			}
			assertProxyCleaned(t, run.config)
		})
	}
}

func TestNpmProxyChainsToAuthenticatedUpstream(t *testing.T) {
	executable, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm required for npm integration tests")
	}
	registry := startNpmRegistry(t)
	var tunnels atomic.Int32
	tunnel := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
	upstream := strings.Replace(tunnel.URL, "://", "://proxy:secret@", 1)
	newNpmTestProject(t, registry, "https-proxy="+upstream+"\n")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	manager, err := npm.NewNpm(context.Background(), "npm", executable)
	if err != nil {
		t.Fatal(err)
	}
	options, err := manager.ProxyOptions([]string{"install", "lab-pkg"})
	if err != nil || options.Upstream.HTTPSProxy != upstream {
		t.Fatalf("upstream = %q (error %v), want the credentialed URL verbatim", options.Upstream.HTTPSProxy, err)
	}
	run := runNpmThroughProxy(t, []string{"install", "lab-pkg"}, evaluation.OutcomeAllow)
	if run.commandErr != nil {
		t.Fatalf("npm failed: %v", run.commandErr)
	}
	if tunnels.Load() < 1 || registry.TarballHits.Load() != 1 || run.calls != 1 {
		t.Fatalf("tunnels=%d tarball downloads=%d evaluations=%d", tunnels.Load(), registry.TarballHits.Load(), run.calls)
	}
	for _, output := range append([]string{logs.String(), run.details}, run.sources...) {
		if strings.Contains(output, "secret") {
			t.Fatalf("upstream credential leaked: %s", output)
		}
	}
	assertProxyCleaned(t, run.config)
}

func TestNpmProxyWithoutUpstreamConnectsDirectly(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm required for npm integration tests")
	}
	registry := startNpmRegistry(t)
	var tunnels atomic.Int32
	proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:secret", hits: &tunnels})
	newNpmTestProject(t, registry, "")
	run := runNpmThroughProxy(t, []string{"install", "lab-pkg"}, evaluation.OutcomeAllow)
	if run.commandErr != nil {
		t.Fatalf("npm failed: %v", run.commandErr)
	}
	if tunnels.Load() != 0 || registry.TarballHits.Load() != 1 {
		t.Fatalf("tunnels=%d tarball downloads=%d, want a direct download", tunnels.Load(), registry.TarballHits.Load())
	}
}
