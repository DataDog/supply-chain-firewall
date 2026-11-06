// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/poetry"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func poetryForProxyTest(t *testing.T) poetry.Poetry {
	t.Helper()
	executable, err := exec.LookPath("poetry")
	if err != nil {
		t.Skip("Poetry required for integration tests")
	}
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "VIRTUAL_ENV", "CONDA_PREFIX", "POETRY_ACTIVE"} {
		t.Setenv(key, "")
	}
	t.Setenv("POETRY_CONFIG_DIR", t.TempDir())
	t.Setenv("POETRY_CACHE_DIR", t.TempDir())
	t.Setenv("POETRY_VIRTUALENVS_IN_PROJECT", "true")
	t.Setenv("POETRY_HTTP_BASIC_PRIVATE_USERNAME", "private")
	t.Setenv("POETRY_HTTP_BASIC_PRIVATE_PASSWORD", "secret")
	t.Setenv("POETRY_REQUESTS_TIMEOUT", "3")
	manager, err := poetry.NewPoetry(context.Background(), "poetry", executable)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func poetryTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

type capturingPoetryRunner struct {
	poetry.Poetry
	config proxy.ClientConfig
}

func (r *capturingPoetryRunner) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	r.config = config
	return r.Poetry.ProxyCommand(ctx, args, config)
}

func assertPoetryProxyCleaned(t *testing.T, config proxy.ClientConfig) {
	t.Helper()
	if config.URL == "" {
		t.Fatal("Poetry command was not configured for interception")
	}
	if _, err := os.Stat(filepath.Dir(config.CACertificatePath)); !os.IsNotExist(err) {
		t.Fatal("invocation CA directory was not removed")
	}
	client := http.Client{Timeout: time.Second}
	if response, err := client.Get(config.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("invocation proxy is still listening")
	}
}

func TestPoetryProxyEndToEnd(t *testing.T) {
	manager := poetryForProxyTest(t)
	projectFixture := readProxyFixture(t, "poetry/pyproject.toml.tmpl")
	localConfig := readProxyFixture(t, "poetry/poetry.toml")
	userConfig := readProxyFixture(t, "poetry/config.toml")
	simple := readProxyFixture(t, "poetry/simple.html")
	wheel := pipWheel(t)
	for _, test := range []struct {
		name, command, priority string
		outcome                 evaluation.Outcome
		cached                  bool
		auth                    string
	}{
		{name: "install", command: "install", priority: "primary", outcome: evaluation.OutcomeAllow},
		{name: "add", command: "add", priority: "primary", outcome: evaluation.OutcomeAllow},
		{name: "update", command: "update", priority: "primary", outcome: evaluation.OutcomeAllow},
		{name: "lock", command: "lock", priority: "primary", outcome: evaluation.OutcomeAllow},
		{name: "warn continues", command: "install", priority: "primary", outcome: evaluation.OutcomeWarn},
		{name: "block install", command: "install", priority: "primary", outcome: evaluation.OutcomeBlock},
		{name: "block add", command: "add", priority: "primary", outcome: evaluation.OutcomeBlock},
		{name: "block update", command: "update", priority: "primary", outcome: evaluation.OutcomeBlock},
		{name: "block lock", command: "lock", priority: "primary", outcome: evaluation.OutcomeBlock},
		{name: "supplemental", command: "install", priority: "supplemental", outcome: evaluation.OutcomeAllow},
		{name: "explicit", command: "install", priority: "explicit", outcome: evaluation.OutcomeAllow},
		{name: "auth file", command: "install", priority: "primary", outcome: evaluation.OutcomeAllow, auth: "file"},
		{name: "keyring", command: "install", priority: "primary", outcome: evaluation.OutcomeAllow, auth: "keyring"},
		{name: "cached metadata block", command: "install", priority: "primary", outcome: evaluation.OutcomeBlock, cached: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("POETRY_CACHE_DIR", filepath.Join(root, "cache"))
			t.Setenv("POETRY_CONFIG_DIR", root)
			config := userConfig
			if test.auth == "file" || test.auth == "keyring" {
				t.Setenv("POETRY_HTTP_BASIC_PRIVATE_PASSWORD", "")
				if err := os.Unsetenv("POETRY_HTTP_BASIC_PRIVATE_PASSWORD"); err != nil {
					t.Fatal(err)
				}
			}
			if test.auth == "file" {
				t.Setenv("POETRY_HTTP_BASIC_PRIVATE_USERNAME", "")
				if err := os.Unsetenv("POETRY_HTTP_BASIC_PRIVATE_USERNAME"); err != nil {
					t.Fatal(err)
				}
				poetryTestFile(t, filepath.Join(root, "auth.toml"), readProxyFixture(t, "poetry/auth.toml"))
			}
			if test.auth == "keyring" {
				config = strings.Replace(config, "enabled = false", "enabled = true", 1)
				poetryTestFile(t, filepath.Join(root, "scfw_test_keyring.py"), readProxyFixture(t, "poetry/keyring.py"))
				t.Setenv("PYTHONPATH", root)
				t.Setenv("PYTHON_KEYRING_BACKEND", "scfw_test_keyring.TestKeyring")
				t.Setenv("SCFW_TEST_KEYRING_READ", filepath.Join(root, "keyring-reads"))
			}
			poetryTestFile(t, filepath.Join(root, "config.toml"), config)
			var downloads, indexes atomic.Int32
			registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, password, ok := r.BasicAuth()
				if !ok || user != "private" || password != "secret" {
					if strings.HasPrefix(r.URL.Path, "/empty/") {
						http.NotFound(w, r)
						return
					}
					http.Error(w, "authentication required", http.StatusUnauthorized)
					return
				}
				switch r.URL.Path {
				case "/python-packages/project/":
					indexes.Add(1)
					w.Header().Set("Content-Type", "text/html")
					w.Header().Set("Cache-Control", "public, max-age=3600")
					_, _ = io.WriteString(w, simple)
				case "/python-packages/packages/project-1.0-py3-none-any.whl":
					downloads.Add(1)
					_, _ = w.Write(wheel)
				default:
					http.NotFound(w, r)
				}
			}))
			defer registry.Close()
			ca := filepath.Join(root, "registry.pem")
			poetryTestFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})))
			t.Setenv("REQUESTS_CA_BUNDLE", ca)
			// Bypass controls are moved to the outbound side, never left on Poetry.
			t.Setenv("NO_PROXY", "*")
			t.Setenv("no_proxy", "*")
			dependency := `project = "1.0"`
			other := ""
			if test.priority != "primary" {
				other = fmt.Sprintf("[[tool.poetry.source]]\nname = 'empty'\nurl = '%s/empty/'\npriority = 'primary'\n", registry.URL)
			}
			if test.priority == "explicit" {
				dependency = `project = {version = "1.0", source = "private"}`
			}
			if test.command == "add" {
				dependency = ""
			}
			manifest := fmt.Sprintf(projectFixture, dependency, other, registry.URL, test.priority)
			poetryTestFile(t, filepath.Join(root, "pyproject.toml"), manifest)
			poetryTestFile(t, filepath.Join(root, "poetry.toml"), localConfig)
			args := []string{"--directory", root, "--no-interaction", test.command}
			if test.command == "install" {
				args = append(args, "--no-root")
			}
			if test.command == "add" {
				args = append(args, "--source", "private", "project==1.0")
			}
			outcome := test.outcome
			var calls atomic.Int32
			var details bytes.Buffer
			configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
				policy := newProxyPackageEvaluator(ctx, time.Now(), args, "poetry", manager.Executable(), "", proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					calls.Add(1)
					if interactive {
						t.Error("Poetry proxy policy evaluation must not prompt")
					}
					for pkg := range targets.Items() {
						if pkg.Name != "project" || pkg.Version != "1.0" || strings.Contains(pkg.Source, "secret") {
							t.Errorf("unexpected package: %+v", pkg)
						}
					}
					return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome}, nil
				}), nopReporter{}, &details)
				options, err := manager.PyPIClassifierOptions(args)
				if err != nil {
					return nil, err
				}
				hook, err := pypi.NewProxyHook(ctx, pypi.ProxyHookOptions{
					Client: client, ClassifierOptions: options, EvaluatePackage: policy.evaluatePackage,
					ResolvePublishDate: func(context.Context, string, string, string) (time.Time, error) {
						return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), nil
					},
				})
				return []proxy.RequestHook{hook}, err
			}
			runner := &capturingPoetryRunner{Poetry: manager}
			var originalLock []byte
			var cachedIndexes int32
			if test.cached {
				outcome = evaluation.OutcomeAllow
				primeArgs := []string{"--directory", root, "--no-interaction", "lock"}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, primeArgs, configure)
				if commandErr != nil || setupErr != nil {
					t.Fatalf("prime cache: %v / %v", commandErr, setupErr)
				}
				assertPoetryProxyCleaned(t, runner.config)
				lock, err := os.ReadFile(filepath.Join(root, "poetry.lock"))
				if err != nil {
					t.Fatal(err)
				}
				originalLock = lock
				cachedIndexes = indexes.Load()
				if err := os.RemoveAll(filepath.Join(root, "cache", "artifacts")); err != nil {
					t.Fatal(err)
				}
				calls.Store(0)
				outcome = test.outcome
			}
			before := downloads.Load()
			commandErr, setupErr := runThroughProxy(context.Background(), runner, args, configure)
			if setupErr != nil {
				t.Fatal(setupErr)
			}
			if test.outcome == evaluation.OutcomeBlock {
				if commandErr == nil {
					t.Fatal("blocked Poetry operation succeeded")
				}
				if downloads.Load() != before {
					t.Fatal("blocked download reached registry")
				}
			} else if commandErr != nil {
				t.Fatal(commandErr)
			}
			if calls.Load() != 1 {
				t.Fatalf("evaluations=%d, want one per package", calls.Load())
			}
			if indexes.Load() == 0 {
				t.Fatal("configured source was not used")
			}
			if test.cached {
				lock, err := os.ReadFile(filepath.Join(root, "poetry.lock"))
				if err != nil || !bytes.Equal(lock, originalLock) {
					t.Fatal("blocked install changed the existing lockfile")
				}
				if indexes.Load() != cachedIndexes {
					t.Fatal("cached source metadata was not reused")
				}
			}
			if test.outcome == evaluation.OutcomeWarn && (!strings.Contains(details.String(), "WARN") || strings.Contains(details.String(), "Proceed")) {
				t.Fatalf("unexpected warning: %s", details.String())
			}
			if test.auth == "keyring" {
				if _, err := os.Stat(filepath.Join(root, "keyring-reads")); err != nil {
					t.Fatal("Poetry did not use the inherited keyring")
				}
			}
			if test.auth == "file" {
				data, err := os.ReadFile(filepath.Join(root, "auth.toml"))
				if err != nil || string(data) != readProxyFixture(t, "poetry/auth.toml") {
					t.Fatal("Poetry credentials changed")
				}
			}
			for name, expected := range map[string]string{"poetry.toml": localConfig, "config.toml": config} {
				data, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(data) != expected {
					t.Fatalf("%s changed", name)
				}
			}
			if test.command != "add" || test.outcome == evaluation.OutcomeBlock {
				data, err := os.ReadFile(filepath.Join(root, "pyproject.toml"))
				if err != nil || string(data) != manifest {
					t.Fatal("project configuration changed")
				}
			}
			if test.outcome != evaluation.OutcomeBlock {
				if _, err := os.Stat(filepath.Join(root, "poetry.lock")); err != nil {
					t.Fatal("Poetry lockfile was not written")
				}
			}
			assertPoetryProxyCleaned(t, runner.config)
		})
	}
}

func TestPoetryProxyPreservesProcess(t *testing.T) {
	manager := poetryForProxyTest(t)
	root := t.TempDir()
	poetryTestFile(t, filepath.Join(root, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
	poetryTestFile(t, filepath.Join(root, "process.py"), readProxyFixture(t, "poetry/process.py"))
	t.Setenv("SCFW_TEST_INHERITED", "unchanged")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "test.inherited")
	t.Setenv("GIT_CONFIG_VALUE_0", "inherited git value")
	stdin, err := os.CreateTemp(root, "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	if _, err := io.WriteString(stdin, "inherited stdin\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	stdout, err := os.CreateTemp(root, "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	stderr, err := os.CreateTemp(root, "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stderr.Close() }()
	originalIn, originalOut, originalErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = stdin, stdout, stderr
	t.Cleanup(func() { os.Stdin, os.Stdout, os.Stderr = originalIn, originalOut, originalErr })
	before := os.Environ()
	runner := &capturingPoetryRunner{Poetry: manager}
	args := []string{"--directory", root, "run", "python", filepath.Join(root, "process.py"), "a value with spaces", "--opaque"}
	commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
	var exit *exec.ExitError
	if setupErr != nil || !errors.As(commandErr, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("process status: %v / %v", commandErr, setupErr)
	}
	for path, expected := range map[string]string{stdout.Name(): "inherited stdout\n", stderr.Name(): "inherited stderr\n"} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), expected) {
			t.Fatalf("missing stream %q: %s / %v", expected, data, err)
		}
	}
	if strings.Join(before, "\n") != strings.Join(os.Environ(), "\n") {
		t.Fatal("parent environment changed")
	}
	assertPoetryProxyCleaned(t, runner.config)
	commandErr, setupErr = runThroughProxy(context.Background(), runner, []string{"--directory", root, "not-a-poetry-command"}, nil)
	if setupErr != nil || !errors.As(commandErr, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("manager failure: %v / %v", commandErr, setupErr)
	}
	assertPoetryProxyCleaned(t, runner.config)
}

// A real forwarding proxy verifies that SCFW uses the original authenticated
// URL for both plain requests and CONNECT, including TLS connections to proxies.
func poetryTestUpstream(t *testing.T, secure bool, hits *atomic.Int32, connectAddress ...string) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy:proxy-secret")) {
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		hits.Add(1)
		if r.Method == http.MethodConnect {
			address := r.Host
			if len(connectAddress) > 0 {
				address = connectAddress[0]
			}
			upstream, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				http.Error(w, "connect failed", http.StatusBadGateway)
				return
			}
			client, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				_ = upstream.Close()
				return
			}
			defer func() { _ = client.Close(); _ = upstream.Close() }()
			_, _ = buffer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
			if err := buffer.Flush(); err != nil {
				return
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
			_, _ = io.Copy(client, upstream)
			_ = client.Close()
			<-done
			return
		}
		request := r.Clone(r.Context())
		request.RequestURI = ""
		request.Header.Del("Proxy-Authorization")
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		response, err := transport.RoundTrip(request)
		if err != nil {
			http.Error(w, "forward failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	server := httptest.NewUnstartedServer(handler)
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func TestPoetryPreservesAuthenticatedUpstream(t *testing.T) {
	manager := poetryForProxyTest(t)
	wheel := pipWheel(t)
	projectFixture := readProxyFixture(t, "poetry/git-pyproject.toml")
	for _, targetTLS := range []bool{false, true} {
		for _, proxyTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("target-tls=%t/proxy-tls=%t", targetTLS, proxyTLS), func(t *testing.T) {
				root := t.TempDir()
				poetryTestFile(t, filepath.Join(root, "pyproject.toml"), projectFixture)
				var downloads, hits atomic.Int32
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					user, password, ok := r.BasicAuth()
					if !ok || user != "private" || password != "source-secret" || r.Header.Get("Proxy-Authorization") != "" {
						t.Error("source/proxy credentials were not preserved separately")
						http.Error(w, "auth required", 401)
						return
					}
					downloads.Add(1)
					_, _ = w.Write(wheel)
				}))
				if targetTLS {
					origin.StartTLS()
				} else {
					origin.Start()
				}
				defer origin.Close()
				upstream := poetryTestUpstream(t, proxyTLS, &hits)
				proxyURL := strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1)
				t.Setenv("http_proxy", proxyURL)
				t.Setenv("https_proxy", proxyURL)
				t.Setenv("POETRY_CACHE_DIR", filepath.Join(root, "cache"))
				var certificates []byte
				if targetTLS {
					certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})...)
				}
				if proxyTLS {
					certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})...)
				}
				if len(certificates) > 0 {
					ca := filepath.Join(root, "origin.pem")
					poetryTestFile(t, ca, string(certificates))
					t.Setenv("REQUESTS_CA_BUNDLE", ca)
				}
				options, err := manager.ProxyOptions(nil)
				if err != nil {
					t.Fatal(err)
				}
				if options.Upstream.HTTPProxy != proxyURL || options.Upstream.HTTPSProxy != proxyURL {
					t.Fatal("original upstream URL was not captured")
				}
				var diagnostics bytes.Buffer
				originalLogger := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&diagnostics, &slog.HandlerOptions{Level: slog.LevelDebug})))
				defer slog.SetDefault(originalLogger)
				artifact := strings.Replace(origin.URL, "://", "://private:source-secret@", 1) + "/project-1.0-py3-none-any.whl"
				runner := &capturingPoetryRunner{Poetry: manager}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, []string{"--directory", root, "--no-interaction", "add", "--lock", artifact}, nil)
				if commandErr != nil || setupErr != nil {
					t.Fatalf("upstream run: %v / %v", commandErr, setupErr)
				}
				if hits.Load() == 0 || downloads.Load() == 0 {
					t.Fatal("original authenticated proxy was not followed")
				}
				if strings.Contains(diagnostics.String(), "proxy-secret") || strings.Contains(diagnostics.String(), "source-secret") {
					t.Fatal("core diagnostics exposed credentials")
				}
				assertPoetryProxyCleaned(t, runner.config)
			})
		}
	}
}

func TestPoetryGitDependenciesUseInvocationTrust(t *testing.T) {
	manager := poetryForProxyTest(t)
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git required")
	}
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	if err := os.Mkdir(repository, 0700); err != nil {
		t.Fatal(err)
	}
	poetryTestFile(t, filepath.Join(repository, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
	for _, args := range [][]string{{"init"}, {"add", "."}, {"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=SCFW Test", "-c", "user.email=scfw@example.invalid", "commit", "-m", "fixture"}} {
		child := exec.Command(gitExecutable, args...)
		child.Dir = repository
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	backend := cgi.Handler{Path: gitExecutable, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	var requests atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); backend.ServeHTTP(w, r) }))
	defer origin.Close()
	ca := filepath.Join(root, "git-ca.pem")
	poetryTestFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})))
	t.Setenv("GIT_SSL_CAINFO", ca)
	var hits atomic.Int32
	upstream := poetryTestUpstream(t, false, &hits)
	t.Setenv("https_proxy", strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1))
	for _, systemGit := range []string{"false", "true"} {
		t.Run("system-git="+systemGit, func(t *testing.T) {
			t.Setenv("POETRY_SYSTEM_GIT_CLIENT", systemGit)
			t.Setenv("POETRY_EXPERIMENTAL_SYSTEM_GIT_CLIENT", systemGit)
			project := t.TempDir()
			t.Setenv("POETRY_CACHE_DIR", filepath.Join(project, "cache"))
			poetryTestFile(t, filepath.Join(project, "pyproject.toml"), strings.Replace(readProxyFixture(t, "poetry/git-pyproject.toml"), `name = "git-project"`, `name = "consumer"`, 1))
			runner := &capturingPoetryRunner{Poetry: manager}
			var observed atomic.Int32
			configure := func(context.Context, *http.Client) ([]proxy.RequestHook, error) {
				return []proxy.RequestHook{func(_ context.Context, request proxy.Request) (proxy.ResponseHook, error) {
					if strings.Contains(request.URL.Path, "repository/.git/") {
						observed.Add(1)
					}
					return nil, nil
				}}, nil
			}
			before := hits.Load()
			commandErr, setupErr := runThroughProxy(context.Background(), runner, []string{"--directory", project, "--no-interaction", "add", "--lock", "git+" + origin.URL + "/repository/.git"}, configure)
			if commandErr != nil || setupErr != nil {
				t.Fatalf("Git dependency: %v / %v", commandErr, setupErr)
			}
			if hits.Load() == before || observed.Load() == 0 || requests.Load() == 0 {
				t.Fatal("Git traffic did not traverse SCFW and the inherited proxy")
			}
			if os.Getenv("GIT_SSL_CAINFO") != ca {
				t.Fatal("parent Git CA changed")
			}
			assertPoetryProxyCleaned(t, runner.config)
		})
	}
}

func TestPoetryPublicPyPIThroughProxy(t *testing.T) {
	manager := poetryForProxyTest(t)
	root := t.TempDir()
	poetryTestFile(t, filepath.Join(root, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
	wheel := pipWheel(t)
	digest := fmt.Sprintf("%x", sha256.Sum256(wheel))
	simple := strings.ReplaceAll(readProxyJSONFixture(t, "poetry/public-simple"), "WHEEL_SHA256", digest)
	metadata := strings.ReplaceAll(readProxyJSONFixture(t, "poetry/public-project"), "WHEEL_SHA256", digest)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"pypi.org", "files.pythonhosted.org"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var downloads atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/project/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, simple)
		case "/pypi/project/json", "/pypi/project/1.0/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, metadata)
		case "/packages/project-1.0-py3-none-any.whl":
			downloads.Add(1)
			_, _ = w.Write(wheel)
		default:
			http.NotFound(w, r)
		}
	}))
	origin.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	origin.StartTLS()
	defer origin.Close()
	ca := filepath.Join(root, "pypi.pem")
	poetryTestFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	t.Setenv("REQUESTS_CA_BUNDLE", ca)
	var hits atomic.Int32
	upstream := poetryTestUpstream(t, false, &hits, origin.Listener.Addr().String())
	t.Setenv("https_proxy", strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1))
	var evaluations atomic.Int32
	configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
		factory, _ := findPackageManagerFactory("poetry")
		hook, err := factory.ProxyHooks[0](ctx, manager, nil, client, func(_ context.Context, pkg pm.Package, publicationErr error) error {
			if pkg.Name != "project" || pkg.Version != "1.0" || publicationErr != nil {
				t.Errorf("public package: %+v / %v", pkg, publicationErr)
			}
			evaluations.Add(1)
			return nil
		})
		return []proxy.RequestHook{hook}, err
	}
	runner := &capturingPoetryRunner{Poetry: manager}
	commandErr, setupErr := runThroughProxy(context.Background(), runner, []string{"--directory", root, "--no-interaction", "add", "project==1.0"}, configure)
	if commandErr != nil || setupErr != nil {
		t.Fatalf("public PyPI: %v / %v", commandErr, setupErr)
	}
	if downloads.Load() == 0 || evaluations.Load() == 0 || hits.Load() == 0 {
		t.Fatal("public PyPI traffic did not traverse the proxy and its package hook")
	}
	assertPoetryProxyCleaned(t, runner.config)
}
