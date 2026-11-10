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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

	"github.com/elazarl/goproxy"
	"github.com/pelletier/go-toml/v2"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/uv"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// Keep configuration variants together; templates and executable scripts retain
// their own fixtures. Read cases before tests change the working directory.
func uvConfigurationFixture(t *testing.T, name string) string {
	t.Helper()
	var cases map[string]map[string]any
	if err := toml.Unmarshal([]byte(readProxyFixture(t, "uv/configurations.toml.tmpl")), &cases); err != nil {
		t.Fatal(err)
	}
	settings, found := cases[name]
	if !found {
		t.Fatalf("unknown uv configuration fixture %q", name)
	}
	content, err := toml.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func uvTestEnvironment(t *testing.T) string {
	t.Helper()
	executable, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv required for integration tests")
	}
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "UV_CONFIG_FILE", "UV_NO_CONFIG", "UV_PROJECT", "UV_WORKING_DIR", "UV_WORKING_DIRECTORY", "UV_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_FIND_LINKS", "UV_INSECURE_HOST", "UV_NATIVE_TLS", "UV_SYSTEM_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSL_CLIENT_CERT", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "VIRTUAL_ENV", "CONDA_PREFIX", "UV_VENV_SEED", "UV_FROZEN", "UV_NO_SYNC", "UV_TOOL_DIR"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UV_NO_SYSTEM_CONFIG", "1")
	t.Setenv("UV_PYTHON_DOWNLOADS", "never")
	t.Setenv("UV_HTTP_RETRIES", "0")
	t.Setenv("UV_NO_PROGRESS", "1")
	t.Setenv("UV_CACHE_DIR", t.TempDir())
	t.Setenv("UV_KEYRING_PROVIDER", "disabled")
	return executable
}

type capturingUVRunner struct {
	uv.UV
	config           proxy.ClientConfig
	invocationConfig string
}

func (runner *capturingUVRunner) ProxyCommand(ctx context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	runner.config = config
	spec, err := runner.UV.ProxyCommand(ctx, command, config)
	runner.invocationConfig = spec.EnvOverrides["UV_CONFIG_FILE"]
	return spec, err
}

func assertUVProxyCleaned(t *testing.T, runner *capturingUVRunner) {
	t.Helper()
	assertProxyCleaned(t, runner.config)
	if runner.invocationConfig != "" {
		if _, err := os.Stat(runner.invocationConfig); !os.IsNotExist(err) {
			t.Fatal("invocation config was not removed")
		}
	}
}

func TestUVProxyEndToEnd(t *testing.T) {
	executable := uvTestEnvironment(t)
	wheel := pypiWheel(t)
	seedWheel := pypiWheelNamed(t, "pip")
	simple := readProxyJSONFixture(t, "uv/simple")
	project := uvConfigurationFixture(t, "pyproject")
	emptyProject := uvConfigurationFixture(t, "empty-project")
	configTemplate := uvConfigurationFixture(t, "uv")
	scriptTemplate := readProxyFixture(t, "uv/script.py.tmpl")
	var artifacts atomic.Int32
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "private" || password != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		switch r.URL.Path {
		case "/custom/pip/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, strings.ReplaceAll(simple, "project", "pip"))
		case "/packages/pip-1.0-py3-none-any.whl":
			if r.Method == http.MethodGet {
				artifacts.Add(1)
			}
			http.ServeContent(w, r, "pip-1.0-py3-none-any.whl", time.Time{}, bytes.NewReader(seedWheel))
		case "/custom/project/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, simple)
		case "/packages/project-1.0-py3-none-any.whl":
			if r.Method == http.MethodGet {
				artifacts.Add(1)
			}
			http.ServeContent(w, r, "project-1.0-py3-none-any.whl", time.Time{}, bytes.NewReader(wheel))
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	certificate := filepath.Join(t.TempDir(), "registry.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certificate)
	t.Setenv("UV_INDEX_PRIVATE_USERNAME", "private")
	t.Setenv("UV_INDEX_PRIVATE_PASSWORD", "secret")
	index := strings.Replace(registry.URL, "https://", "https://private:secret@", 1) + "/custom/"
	var upstreamHits atomic.Int32
	upstream := goproxy.NewProxyHttpServer()
	upstream.ConnectDial = net.Dial
	upstream.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		upstreamHits.Add(1)
		return goproxy.OkConnect, host
	})
	upstreamServer := httptest.NewServer(upstream)
	defer upstreamServer.Close()
	for _, operation := range []string{"pip-install", "pip-sync", "pip-compile", "pip-file-proxy", "pip-cert", "pip-python-preference", "pip-python-fetch", "pip-preview-feature", "add", "sync", "lock", "script", "script-file-proxy", "uvx", "uvx-absolute", "uvx-relative", "version-bump", "version-value", "version-no-sync", "venv-seed", "venv-seed-env"} {
		for _, outcome := range []evaluation.Outcome{evaluation.OutcomeAllow, evaluation.OutcomeWarn, evaluation.OutcomeBlock} {
			t.Run(operation+"/"+string(outcome), func(t *testing.T) {
				t.Chdir(t.TempDir())
				t.Setenv("UV_CACHE_DIR", t.TempDir())
				if err := os.WriteFile("pyproject.toml", []byte(project), 0600); err != nil {
					t.Fatal(err)
				}
				command := []string{"--no-config", "--no-python-downloads"}
				if strings.HasPrefix(operation, "pip-") {
					child := exec.Command(executable, "venv", "--no-config", ".venv")
					if output, err := child.CombinedOutput(); err != nil {
						t.Fatalf("create virtualenv: %v %s", err, output)
					}
					pipCommand := strings.TrimPrefix(operation, "pip-")
					if operation == "pip-file-proxy" || operation == "pip-cert" || strings.HasPrefix(operation, "pip-python-") || operation == "pip-preview-feature" {
						pipCommand = "install"
					}
					command = append(command, "pip", pipCommand)
					switch operation {
					case "pip-install", "pip-file-proxy", "pip-cert", "pip-python-preference", "pip-python-fetch", "pip-preview-feature":
						command = append(command, "project==1.0")
					default:
						if err := os.WriteFile("requirements.txt", []byte("project==1.0\n"), 0600); err != nil {
							t.Fatal(err)
						}
						command = append(command, "requirements.txt")
					}
				} else {
					command = append(command, operation)
					if operation == "add" {
						if err := os.WriteFile("pyproject.toml", []byte(emptyProject), 0600); err != nil {
							t.Fatal(err)
						}
						command = append(command, "project==1.0")
					}
				}
				executableName, managerExecutable, packageName := "uv", executable, "project"
				switch operation {
				case "uvx", "uvx-absolute", "uvx-relative":
					var err error
					managerExecutable, err = exec.LookPath("uvx")
					if err != nil {
						t.Skip("uvx required")
					}
					executableName = "uvx"
					command = []string{"--no-config", "--no-python-downloads", "--from", "project==1.0"}
					t.Setenv("UV_TOOL_DIR", t.TempDir())
				case "version-bump", "version-no-sync":
					command = []string{"--no-config", "version", "--bump", "patch"}
					if operation == "version-no-sync" {
						command = append(command, "--no-sync")
					}
				case "version-value":
					command = []string{"--no-config", "version", "2.0"}
				case "venv-seed", "venv-seed-env":
					python, err := exec.LookPath("python3")
					if err != nil {
						t.Skip("Python 3.12+ required for the pip-only seed fixture")
					}
					versionOutput, err := exec.Command(python, "--version").Output()
					fields := strings.Fields(string(versionOutput))
					if err != nil || len(fields) < 2 {
						t.Fatalf("query Python version: %v %s", err, versionOutput)
					}
					version, err := pm.ParseVersion(fields[1])
					if err != nil {
						t.Fatal(err)
					}
					if version.LessThan(pm.Version{Major: 3, Minor: 12}) {
						t.Skip("Python 3.12+ required for the pip-only seed fixture")
					}
					command = []string{"--no-config", "venv", "--python", python, ".venv"}
					if operation == "venv-seed" {
						command = append(command, "--seed")
					} else {
						t.Setenv("UV_VENV_SEED", "1")
					}
					packageName = "pip"
				}
				var originalConfig []byte
				var originalScript []byte
				wantCertificate := certificate
				beforeUpstream := upstreamHits.Load()
				if operation == "pip-file-proxy" || operation == "script-file-proxy" {
					command = command[1:] // Retain uv's configuration discovery.
					originalConfig = []byte(fmt.Sprintf(configTemplate, upstreamServer.URL, upstreamServer.URL, registry.URL))
					if err := os.WriteFile("uv.toml", originalConfig, 0600); err != nil {
						t.Fatal(err)
					}
				} else if operation != "script" {
					command = append(command, "--index-url", index)
				}
				switch operation {
				case "pip-python-preference":
					command = append([]string{"--python-preference", "only-system"}, command...)
				case "pip-python-fetch":
					command = append([]string{"--python-fetch", "never"}, command...)
				case "pip-preview-feature":
					command = append([]string{"--preview-feature", "scfw-parser-test"}, command...)
				case "script", "script-file-proxy":
					command[len(command)-1] = "lock"
					command = append(command, "--script", "script.py")
					originalScript = []byte(fmt.Sprintf(scriptTemplate, index, strings.TrimPrefix(registry.URL, "https://")))
					if err := os.WriteFile("script.py", originalScript, 0600); err != nil {
						t.Fatal(err)
					}
					// The inline trust setting must reach the core, even with --no-config.
					t.Setenv("SSL_CERT_FILE", "")
					wantCertificate = ""
				}
				if operation == "pip-cert" {
					command = append(command, "--cert", filepath.Base(certificate), "--native-tls", "--directory", filepath.Dir(certificate), "--target", t.TempDir())
				}
				if strings.HasPrefix(operation, "uvx") {
					command = append(command, "python", "-c", "import project", "--help")
				}
				invocationName := executableName
				switch operation {
				case "uvx-absolute":
					invocationName = managerExecutable
				case "uvx-relative":
					working, err := os.Getwd()
					if err != nil {
						t.Fatal(err)
					}
					invocationName, err = filepath.Rel(working, managerExecutable)
					if err != nil {
						t.Fatal(err)
					}
				}
				manager, err := uv.NewUV(context.Background(), invocationName, managerExecutable)
				if err != nil {
					t.Fatal(err)
				}
				if !manager.ProxyCommandSupported(command) {
					t.Fatalf("package operation selected for unproxied execution: %v", command)
				}
				runner := &capturingUVRunner{UV: manager}
				var calls, reports atomic.Int32
				var output bytes.Buffer
				evaluator := proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					calls.Add(1)
					if interactive || targets.Len() != 1 {
						t.Error("expected one non-interactive evaluation")
					}
					for pkg := range targets.Items() {
						if pkg.Name != packageName || pkg.Version != "1.0" || pkg.PublishDate.IsZero() {
							t.Errorf("unexpected package: %+v", pkg)
						}
					}
					return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome, Results: []evaluation.PackageEvaluationResult{{Ecosystem: "pypi", PackageName: packageName, PackageVersion: "1.0", Outcome: outcome}}}, nil
				})
				reporter := proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, name, _, _ string, _ *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
					if name != executableName {
						t.Errorf("reported manager = %q", name)
					}
					reports.Add(1)
					return nil
				})
				factory, found := findPackageManagerFactory(executableName)
				if !found || len(factory.ProxyHooks) != 1 {
					t.Fatal("uv registration is missing")
				}
				configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
					evaluation := newProxyPackageEvaluator(ctx, time.Now(), append([]string{executableName}, command...), executableName, managerExecutable, "", evaluator, reporter, &output)
					hook, err := factory.ProxyHooks[0](ctx, manager, command, client, evaluation.evaluatePackage)
					return []proxy.RequestHook{hook}, err
				}
				before := artifacts.Load()
				commandErr, setupErr := runThroughProxy(context.Background(), runner, command, configure)
				if setupErr != nil {
					t.Fatal(setupErr)
				}
				if outcome == evaluation.OutcomeBlock {
					if commandErr == nil || artifacts.Load() != before {
						t.Fatalf("block failed: err=%v fetches=%d", commandErr, artifacts.Load()-before)
					}
				} else if commandErr != nil {
					t.Fatal(commandErr)
				}
				if calls.Load() != 1 || reports.Load() != 1 {
					t.Fatalf("evaluations=%d reports=%d output=%s", calls.Load(), reports.Load(), output.String())
				}
				if outcome == evaluation.OutcomeWarn && (!strings.Contains(output.String(), "WARN") || strings.Contains(output.String(), "Proceed")) {
					t.Fatalf("unexpected warning: %s", output.String())
				}
				assertUVProxyCleaned(t, runner)
				if originalConfig != nil {
					content, err := os.ReadFile("uv.toml")
					if err != nil || !bytes.Equal(content, originalConfig) || upstreamHits.Load() == beforeUpstream {
						t.Fatal("file proxy routing or original uv configuration was not preserved")
					}
				}
				if outcome == evaluation.OutcomeAllow && operation == "pip-install" {
					before := artifacts.Load()
					// A second offline install must retain uv's own cache and venv.
					commandErr, setupErr := runThroughProxy(context.Background(), runner, append(command, "--offline", "--target", t.TempDir()), configure)
					if commandErr != nil || setupErr != nil || artifacts.Load() != before || calls.Load() != 1 {
						t.Fatalf("cached install: %v/%v calls=%d", commandErr, setupErr, calls.Load())
					}
					assertUVProxyCleaned(t, runner)
				}
				if operation == "sync" && outcome == evaluation.OutcomeAllow {
					lockfile, err := os.ReadFile("uv.lock")
					if err != nil {
						t.Fatal(err)
					}
					commandErr, setupErr := runThroughProxy(context.Background(), runner, append(command, "--locked", "--offline"), configure)
					updated, err := os.ReadFile("uv.lock")
					if commandErr != nil || setupErr != nil || err != nil || !bytes.Equal(updated, lockfile) {
						t.Fatalf("locked sync changed lockfile: %v/%v/%v", commandErr, setupErr, err)
					}
					content, err := os.ReadFile("pyproject.toml")
					if err != nil || string(content) != project {
						t.Fatal("sync modified project configuration")
					}
					assertUVProxyCleaned(t, runner)
				}
				if originalScript != nil {
					content, err := os.ReadFile("script.py")
					if err != nil || !bytes.Equal(content, originalScript) {
						t.Fatal("inline script was modified")
					}
					if outcome == evaluation.OutcomeAllow {
						lock := []string{"--offline", "--no-config", "lock", "--script", "script.py"}
						commandErr, setupErr := runThroughProxy(context.Background(), runner, lock, configure)
						if commandErr != nil || setupErr != nil {
							t.Fatalf("locking cached script: %v/%v", commandErr, setupErr)
						}
						assertUVProxyCleaned(t, runner)
						lockfile, err := os.ReadFile("script.py.lock")
						if err != nil {
							t.Fatal(err)
						}
						cached := append([]string{"--offline"}, command...)
						commandErr, setupErr = runThroughProxy(context.Background(), runner, cached, configure)
						if commandErr != nil || setupErr != nil || calls.Load() != 1 {
							t.Fatalf("cached script lock: %v/%v calls=%d", commandErr, setupErr, calls.Load())
						}
						updated, err := os.ReadFile("script.py.lock")
						if err != nil || !bytes.Equal(updated, lockfile) {
							t.Fatal("locking cached script changed its lockfile")
						}
						assertUVProxyCleaned(t, runner)
					}
				}
				if os.Getenv("SSL_CERT_FILE") != wantCertificate {
					t.Fatal("parent trust changed")
				}
			})
		}
	}
}

func TestUVScriptProxyRejectedBeforeExecution(t *testing.T) {
	executable := uvTestEnvironment(t)
	template := readProxyFixture(t, "uv/script-proxy.py.tmpl")
	for _, scheme := range []string{"http-proxy", "https-proxy"} {
		t.Run(scheme, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "script.py")
			original := []byte(fmt.Sprintf(template, scheme))
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			entrypoint := filepath.Join(filepath.Dir(path), "entrypoint")
			if err := os.WriteFile(entrypoint, original, 0600); err != nil {
				t.Fatal(err)
			}
			caller := t.TempDir()
			nested := filepath.Join(filepath.Dir(path), "nested")
			if err := os.Mkdir(nested, 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(caller, "link")
			if err := os.Symlink(nested, link); err != nil {
				t.Fatal(err)
			}
			for _, command := range [][]string{
				{"--no-config", "run", path}, {"run", "--script", path}, {"run", "--", path},
				{"run", "-s", entrypoint}, {"run", "-vs", entrypoint}, {"run", "-vp", "3.12", "-s", entrypoint},
				{"--directory", link + "/..", "run", "script.py"}, {"run", link + "/../script.py"},
				{"run", "--editable", path},
				{"add", "--script", path, "project"}, {"lock", "--script", path},
			} {
				manager, err := uv.NewUV(context.Background(), "uv", executable)
				if err != nil {
					t.Fatal(err)
				}
				runner := &capturingUVRunner{UV: manager}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, command, nil)
				if commandErr != nil || setupErr == nil || !strings.Contains(setupErr.Error(), "inline script proxy") || strings.Contains(setupErr.Error(), "credential-secret") {
					t.Fatalf("rejection: %v/%v", commandErr, setupErr)
				}
				if runner.config.URL != "" {
					t.Fatal("rejected script reached command setup")
				}
			}
			content, _ := os.ReadFile(path)
			if !bytes.Equal(content, original) {
				t.Fatal("rejected script was modified")
			}
		})
	}
}

func TestUVUnsupportedScriptsPreserveInput(t *testing.T) {
	executable := uvTestEnvironment(t)
	input := readProxyFixture(t, "uv/script-proxy.py.tmpl")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	original := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = original }()
	for _, target := range []string{"-", "https://user:credential-secret@example.invalid/script.py"} {
		manager, err := uv.NewUV(context.Background(), "uv", executable)
		if err != nil {
			t.Fatal(err)
		}
		runner := &capturingUVRunner{UV: manager}
		commandErr, setupErr := runThroughProxy(context.Background(), runner, []string{"run", "--", target}, nil)
		if commandErr != nil || setupErr == nil || strings.Contains(setupErr.Error(), "credential-secret") || runner.config.URL != "" {
			t.Fatalf("unsupported script reached execution: %v/%v", commandErr, setupErr)
		}
	}
	remaining, err := io.ReadAll(reader)
	if err != nil || string(remaining) != input {
		t.Fatalf("stdin was consumed: %v", err)
	}
}

// Each scheme uses a distinct authenticated upstream, even though uv itself
// receives one loopback URL. Explicit uv configuration overrides environment.
func TestUVOriginalUpstreamProxies(t *testing.T) {
	executable := uvTestEnvironment(t)
	var logs bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })
	fixture := uvConfigurationFixture(t, "uv")
	for _, scheme := range []string{"http", "https"} {
		for _, fileConfig := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/file-config=%v", scheme, fileConfig), func(t *testing.T) {
				t.Chdir(t.TempDir())
				var hits atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Proxy-Authorization") != "Basic cHJveHk6c2VjcmV0" {
						t.Error("original proxy authentication was lost")
					}
					hits.Add(1)
					if r.Method == http.MethodConnect {
						// A failed CONNECT is enough to prove HTTPS chaining without
						// touching the network or depending on a public registry.
						http.Error(w, "fixture upstream", http.StatusBadGateway)
						return
					}
					http.NotFound(w, r)
				}))
				defer upstream.Close()
				originalProxy := strings.Replace(upstream.URL, "http://", "http://proxy:secret@", 1)
				index := scheme + "://registry.example/custom/"
				args := []string{"pip", "compile", "requirements.txt", "--index-url", index}
				if err := os.WriteFile("requirements.txt", []byte("project==1.0\n"), 0600); err != nil {
					t.Fatal(err)
				}
				var original []byte
				if fileConfig {
					original = []byte(fmt.Sprintf(fixture, originalProxy, originalProxy, scheme+"://registry.example"))
					if err := os.WriteFile("uv.toml", original, 0600); err != nil {
						t.Fatal(err)
					}
					t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
					t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
					t.Setenv("UV_INDEX_PRIVATE_USERNAME", "private")
					t.Setenv("UV_INDEX_PRIVATE_PASSWORD", "secret")
				} else {
					t.Setenv(strings.ToUpper(scheme)+"_PROXY", originalProxy)
				}
				manager, err := uv.NewUV(context.Background(), "uv", executable)
				if err != nil {
					t.Fatal(err)
				}
				runner := &capturingUVRunner{UV: manager}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
				if setupErr != nil || commandErr == nil || hits.Load() == 0 {
					t.Fatalf("upstream chaining failed: %v/%v hits=%d", commandErr, setupErr, hits.Load())
				}
				assertUVProxyCleaned(t, runner)
				if strings.Contains(logs.String(), "proxy:secret") || strings.Contains(logs.String(), "cHJveHk6c2VjcmV0") {
					t.Fatal("proxy credentials were logged")
				}
				if fileConfig {
					content, err := os.ReadFile("uv.toml")
					if err != nil || !bytes.Equal(content, original) {
						t.Fatal("uv configuration was modified")
					}
				}
			})
		}
	}
}

func TestUVFailuresAndSignalsCleanUp(t *testing.T) {
	uvTestEnvironment(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required")
	}
	fixture := readProxyFixture(t, "uv/process.py")
	for _, mode := range []string{"exit", "signal", "uvx-exit", "uvx-signal"} {
		t.Run(mode, func(t *testing.T) {
			t.Chdir(t.TempDir())
			launcher := filepath.Join(t.TempDir(), "uv")
			if err := os.WriteFile(launcher, []byte("#!"+python+"\n"+fixture), 0700); err != nil {
				t.Fatal(err)
			}
			result := filepath.Join(t.TempDir(), "result.json")
			t.Setenv("SCFW_UV_TEST_RESULT", result)
			t.Setenv("SCFW_UV_TEST_MODE", strings.TrimPrefix(mode, "uvx-"))
			name := "uv"
			if strings.HasPrefix(mode, "uvx-") {
				name = "uvx"
			}
			manager, err := uv.NewUV(context.Background(), name, launcher)
			if err != nil {
				t.Fatal(err)
			}
			runner := &capturingUVRunner{UV: manager}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if strings.HasSuffix(mode, "signal") {
				go func() {
					for ctx.Err() == nil {
						if _, err := os.Stat(result + ".ready"); err == nil {
							cancel()
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				}()
			}
			args := []string{"pip", "install", "argument with spaces", "--literal=value"}
			commandErr, setupErr := runThroughProxy(ctx, runner, args, nil)
			exit, ok := errors.AsType[*exec.ExitError](commandErr)
			want := 23
			if strings.HasSuffix(mode, "signal") {
				want = 42
			}
			if setupErr != nil || !ok || exit.ExitCode() != want {
				t.Fatalf("exit/signal propagation: %v/%v", commandErr, setupErr)
			}
			content, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			var state struct {
				Args      []string
				Proxy, CA string
				GitCA     string `json:"git_ca"`
			}
			if err := json.Unmarshal(content, &state); err != nil || !slices.Equal(state.Args, args) || state.Proxy != runner.config.URL || state.CA != runner.config.CACertificatePath || state.GitCA != runner.config.AdditionalClients["git"].CACertificatePath {
				t.Fatalf("child arguments/environment: %+v, %v", state, err)
			}
			assertUVProxyCleaned(t, runner)
		})
	}
}

func TestUVGitDependencyUsesInvocationTrust(t *testing.T) {
	executable := uvTestEnvironment(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git required")
	}
	tarball := pypiSdist(t)
	t.Chdir(t.TempDir())
	directory := t.TempDir()
	reader, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, filepath.Base(header.Name)), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = reader.Close()
	for _, args := range [][]string{{"init"}, {"add", "."}, {"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=SCFW Test", "-c", "user.email=scfw@example.invalid", "commit", "-m", "fixture"}, {"update-server-info"}} {
		child := exec.Command("git", args...)
		child.Dir = directory
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	var requests atomic.Int32
	files := http.FileServer(http.Dir(filepath.Join(directory, ".git")))
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "private" || password != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		requests.Add(1)
		files.ServeHTTP(w, r)
	}))
	defer registry.Close()
	certificate := filepath.Join(t.TempDir(), "git-ca.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	// Registry trust and native Git trust use independent clients and roots.
	_, unrelatedCA, _ := proxyTLSIdentity(t)
	t.Setenv("SSL_CERT_FILE", writeProxyTLSFile(t, unrelatedCA))
	var hits atomic.Int32
	upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "git:secret", hits: &hits})
	originalProxy := strings.Replace(upstream.URL, "://", "://git:secret@", 1)
	for _, source := range []string{"environment", "configuration", "username configuration", "public key pin", "unrelated origin proxy"} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("UV_CACHE_DIR", t.TempDir())
			t.Setenv("GIT_SSL_CAINFO", "")
			if source == "environment" {
				t.Setenv("GIT_SSL_CAINFO", certificate)
			}
			t.Setenv("GIT_CONFIG_COUNT", "3")
			t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
			t.Setenv("GIT_CONFIG_VALUE_0", originalProxy)
			scope := registry.URL
			if source == "username configuration" {
				scope = strings.Replace(scope, "https://", "https://private@", 1)
				t.Setenv("GIT_CONFIG_VALUE_0", "http://unused-proxy.invalid:8080")
			}
			t.Setenv("GIT_CONFIG_KEY_1", "http."+scope+"/.proxy")
			t.Setenv("GIT_CONFIG_VALUE_1", originalProxy)
			caKey := "http.sslCAInfo"
			if source == "username configuration" {
				caKey = "http." + scope + "/.sslCAInfo"
			}
			t.Setenv("GIT_CONFIG_KEY_2", caKey)
			t.Setenv("GIT_CONFIG_VALUE_2", certificate)
			if source == "public key pin" {
				publicKey, err := x509.MarshalPKIXPublicKey(registry.Certificate().PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(publicKey)
				t.Setenv("GIT_CONFIG_COUNT", "4")
				t.Setenv("GIT_CONFIG_KEY_3", "http.pinnedPubkey")
				t.Setenv("GIT_CONFIG_VALUE_3", "sha256//"+base64.StdEncoding.EncodeToString(digest[:]))
			}
			if source == "unrelated origin proxy" {
				t.Setenv("GIT_CONFIG_COUNT", "4")
				t.Setenv("GIT_CONFIG_KEY_3", "remote.origin.proxy")
				t.Setenv("GIT_CONFIG_VALUE_3", "http://unused-origin-proxy.invalid:8080")
			}
			manager, err := uv.NewUV(context.Background(), "uv", executable)
			if err != nil {
				t.Fatal(err)
			}
			runner := &capturingUVRunner{UV: manager}
			vcsURL := "git+" + strings.Replace(registry.URL, "https://", "https://private:secret@", 1)
			args := []string{"pip", "install", "--no-config", "--no-deps", "--no-build-isolation", "--no-index", "--target", t.TempDir(), vcsURL}
			var observed atomic.Int32
			configure := func(context.Context, *http.Client) ([]proxy.RequestHook, error) {
				return []proxy.RequestHook{func(context.Context, proxy.Request) (proxy.ResponseHook, error) { observed.Add(1); return nil, nil }}, nil
			}
			before := hits.Load()
			commandErr, setupErr := runThroughProxy(context.Background(), runner, args, configure)
			if setupErr != nil || commandErr != nil || requests.Load() == 0 || observed.Load() == 0 || hits.Load() == before {
				t.Fatalf("Git dependency: %v/%v origin=%d observed=%d upstream=%d", commandErr, setupErr, requests.Load(), observed.Load(), hits.Load()-before)
			}
			assertUVProxyCleaned(t, runner)
			expectedCount := "3"
			if source == "public key pin" || source == "unrelated origin proxy" {
				expectedCount = "4"
			}
			if os.Getenv("GIT_CONFIG_COUNT") != expectedCount || os.Getenv("GIT_CONFIG_VALUE_1") != originalProxy {
				t.Fatal("parent Git settings changed")
			}
		})
	}
}

func TestUVUnrelatedCommandBypassesProxySetup(t *testing.T) {
	executablePath := uvTestEnvironment(t)
	t.Setenv(proxyEnabledVar, "1")
	t.Setenv(evaluationModeVar, string(evaluationModeDatadog))
	t.Setenv("SSL_CERT_FILE", "/nonexistent-scfw-uv-certificate")
	t.Setenv("HTTPS_PROXY", "http://invalid:port")
	originalExecutable := executable
	t.Cleanup(func() {
		executable = originalExecutable
		runCmd.Flags().Lookup("executable").Changed = false
	})
	cmd := RootCmd()
	defer cmd.RemoveCommand(configureCmd, doctorCmd, runCmd)
	cmd.SetArgs([]string{"run", "--executable", executablePath, "--", "uv", "--version"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("unrelated uv command tried to configure the proxy: %v", err)
	}
}

func TestUVRunBypassesProxySetup(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required")
	}
	fixture := readProxyFixture(t, "uv/process.py")
	t.Chdir(t.TempDir())
	launcher := filepath.Join(t.TempDir(), "uv")
	if err := os.WriteFile(launcher, []byte("#!"+python+"\n"+fixture), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(proxyEnabledVar, "1")
	t.Setenv(evaluationModeVar, string(evaluationModeDatadog))
	// These settings would fail SCFW proxy setup; direct execution must leave them alone.
	for key, value := range map[string]string{
		"HTTPS_PROXY": "http://invalid:port", "SSL_CERT_FILE": "/nonexistent-scfw-uv-certificate",
		"GIT_SSL_CAINFO": "/nonexistent-scfw-git-certificate", "UV_CONFIG_FILE": "/nonexistent-scfw-uv.toml",
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.proxy", "GIT_CONFIG_VALUE_0": "http://original.example",
		"SCFW_UV_TEST_MODE": "passthrough",
	} {
		t.Setenv(key, value)
	}
	originalExecutable := executable
	t.Cleanup(func() {
		executable = originalExecutable
		runCmd.Flags().Lookup("executable").Changed = false
	})
	cmd := RootCmd()
	defer cmd.RemoveCommand(configureCmd, doctorCmd, runCmd)
	for _, args := range [][]string{
		{"run", "python", "argument with spaces", "--help"},
		{"run", "--with", "project==1.0", "python", "app.py"},
		{"run", "--with-requirements", "requirements.txt", "python", "app.py"},
		{"--directory", "project with spaces", "run", "--script", "script.py"},
		{"run", "https://example.invalid/script.py"},
		{"run", "--", "-"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			result := filepath.Join(t.TempDir(), "result.json")
			t.Setenv("SCFW_UV_TEST_RESULT", result)
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close(); _ = writer.Close() }()
			const stdin = "print('stdin stays with uv')\n"
			if _, err := io.WriteString(writer, stdin); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			originalStdin := os.Stdin
			os.Stdin = input
			t.Cleanup(func() { os.Stdin = originalStdin })
			cmd.SetArgs(append([]string{"run", "--executable", launcher, "--", "uv"}, args...))
			if err := cmd.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("uv run tried to configure the proxy: %v", err)
			}
			content, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			var state struct {
				Args                     []string
				Proxy, CA, Config, Stdin string
				GitCA                    string `json:"git_ca"`
				GitConfig                string `json:"git_config"`
			}
			if err := json.Unmarshal(content, &state); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(state.Args, args) || state.Stdin != stdin || state.Proxy != os.Getenv("HTTPS_PROXY") || state.CA != os.Getenv("SSL_CERT_FILE") || state.GitCA != os.Getenv("GIT_SSL_CAINFO") || state.Config != os.Getenv("UV_CONFIG_FILE") || state.GitConfig != os.Getenv("GIT_CONFIG_VALUE_0") {
				t.Fatalf("uv run arguments, input, or environment changed: %+v", state)
			}
		})
	}
}
