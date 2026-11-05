// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/pip"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func pipWheel(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range []string{"project/__init__.py", "project-1.0.dist-info/METADATA", "project-1.0.dist-info/WHEEL", "project-1.0.dist-info/RECORD"} {
		body := readProxyFixture(t, filepath.Join("pip", "wheel", name))
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func pipSdist(t *testing.T, files ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressed)
	// A stdlib-only PEP 517 backend avoids network access to install build tools.
	if len(files) == 0 {
		files = []string{"pyproject.toml", "backend.py", "PKG-INFO"}
	}
	for _, name := range files {
		body := readProxyFixture(t, filepath.Join("pip", "sdist", name))
		if err := writer.WriteHeader(&tar.Header{Name: "project-1.0/" + name, Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, body); err != nil {
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

func TestPipProxyEndToEnd(t *testing.T) {
	nestedRequirements := readProxyFixture(t, "requirements/nested.txt")
	latin1Requirements := readProxyFixture(t, "requirements/latin1.txt.tmpl")
	findLinksRequirements := readProxyFixture(t, "requirements/find-links.txt.tmpl")
	quotedRequirements := readProxyFixture(t, "requirements/quoted.txt.tmpl")
	privateRequirements := readProxyFixture(t, "requirements/private.txt.tmpl")
	directRequirements := readProxyFixture(t, "requirements/direct.txt.tmpl")
	wheelhouseRootFixture := readProxyFixture(t, "pip/wheelhouse-root.html")
	wheelhouseFixture := readProxyFixture(t, "pip/wheelhouse.html")
	simpleFixture := readProxyFixture(t, "pip/simple.html")
	primeCacheFixture := readProxyFixture(t, "pip/prime-cache.py")
	shimFixture := readProxyFixture(t, "pip/shim.sh")
	localLinksFixture := readProxyFixture(t, "pip/local-links.html.tmpl")
	for _, alias := range []string{"pip", "pip3"} {
		t.Run(alias, func(t *testing.T) {
			executable, err := exec.LookPath(alias)
			if err != nil {
				t.Skip("pip required for integration tests")
			}
			for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "PIP_PROXY", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CLIENT_CERT", "PIP_TRUSTED_HOST", "PIP_EXTRA_INDEX_URL"} {
				t.Setenv(key, "")
			}
			t.Setenv("PIP_CONFIG_FILE", os.DevNull)
			t.Setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
			// A parent's bypass must not let pip escape interception.
			t.Setenv("NO_PROXY", "*")
			t.Setenv("no_proxy", "*")
			wheel, sdist := pipWheel(t), pipSdist(t)
			var artifacts, nestedBodies, linksBodies atomic.Int32
			registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, password, ok := r.BasicAuth()
				if !ok || user != "private" || password != "secret" {
					http.Error(w, "authentication required", 401)
					return
				}
				switch r.URL.Path {
				case "/packages/project-1.0-py3-none-any.whl", "/packages/owner's/project-1.0-py3-none-any.whl":
					artifacts.Add(1)
					w.Header().Set("Cache-Control", "public, max-age=3600")
					_, _ = w.Write(wheel)
				case "/packages/project-1.0.tar.gz":
					artifacts.Add(1)
					_, _ = w.Write(sdist)
				case "/requirements.txt", "/requirements.gz":
					if r.URL.Path == "/requirements.gz" {
						w.Header().Set("Content-Encoding", "gzip")
						zipped := gzip.NewWriter(w)
						defer func() { _ = zipped.Close() }()
						_, _ = io.WriteString(zipped, nestedRequirements)
						return
					}
					_, _ = io.WriteString(w, nestedRequirements)
				case "/latin1.txt":
					w.Header().Set("Content-Type", "text/plain; charset=iso-8859-1")
					_, _ = fmt.Fprintf(w, latin1Requirements, r.Host)
				case "/links-requirements.txt":
					_, _ = fmt.Fprintf(w, findLinksRequirements, r.Host)
				case "/original/requirements.txt":
					w.Header().Set("Location", "/moved/requirements.txt")
					w.WriteHeader(http.StatusFound)
				case "/moved/requirements.txt":
					_, _ = io.WriteString(w, nestedRequirements)
				case "/quoted.txt":
					_, _ = fmt.Fprintf(w, quotedRequirements, r.Host)
				case "/nested.txt", "/original/nested.txt":
					nestedBodies.Add(1)
					w.Header().Set("Cache-Control", "public, max-age=3600")
					_, _ = fmt.Fprintf(w, privateRequirements, r.Host)
				case "/wheelhouse/", "/wheelhouse.gz":
					w.Header().Set("Cache-Control", "public, max-age=3600")
					w.Header().Set("Content-Type", "text/html")
					w.Header().Set("ETag", `"wheelhouse-v1"`)
					// Older pip revalidates fresh HTML listings. A 304 still reuses
					// the cached body, so count only responses that send the listing.
					if r.Header.Get("If-None-Match") == `"wheelhouse-v1"` {
						w.WriteHeader(http.StatusNotModified)
						return
					}
					linksBodies.Add(1)
					if r.URL.Path == "/wheelhouse.gz" {
						w.Header().Set("Content-Encoding", "gzip")
						zipped := gzip.NewWriter(w)
						defer func() { _ = zipped.Close() }()
						_, _ = io.WriteString(zipped, wheelhouseRootFixture)
						return
					}
					_, _ = io.WriteString(w, wheelhouseFixture)
				case "/simple/project/", "/private-index/project/":
					w.Header().Set("Content-Type", "text/html")
					_, _ = io.WriteString(w, simpleFixture)
				default:
					http.NotFound(w, r)
				}
			}))
			defer registry.Close()
			ca := filepath.Join(t.TempDir(), "registry.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PIP_CERT", ca)
			manager, err := pip.NewPip(context.Background(), alias, executable)
			if err != nil {
				t.Fatal(err)
			}
			base := strings.Replace(registry.URL, "https://", "https://private:secret@", 1)
			for _, test := range []struct {
				name, command, artifact      string
				outcome                      evaluation.Outcome
				requirements, isolated, shim bool
				mode                         string
			}{
				{name: "install-wheel", command: "install", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeAllow},
				{name: "download-requirements", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeAllow, requirements: true},
				{name: "wheel-isolated", command: "wheel", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeAllow, isolated: true},
				{name: "download-sdist", command: "download", artifact: "project-1.0.tar.gz", outcome: evaluation.OutcomeAllow},
				{name: "build-sdist", command: "wheel", artifact: "project-1.0.tar.gz", outcome: evaluation.OutcomeAllow},
				{name: "warn-continues", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeWarn},
				{name: "gzip-requirements-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "gzip-remote"},
				{name: "gzip-find-links-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "gzip-links"},
				{name: "remote-requirements-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "remote"},
				{name: "find-links-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "links"},
				{name: "local-html-links-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "local-links"},
				{name: "private-index-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "index"},
				{name: "redirected-requirements-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "redirect-remote"},
				{name: "cached-inner-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "cached-inner"},
				{name: "cached-links-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "cached-links"},
				{name: "quoted-direct-block", command: "download", artifact: "owner's/project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock},
				{name: "latin1-remote-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "latin1-remote"},
				{name: "quoted-remote-block", command: "download", artifact: "owner's/project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "quoted-remote"},
				{name: "block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock},
				{name: "shell-shim-download", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeAllow, shim: true},
				{name: "shell-shim-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, shim: true},
				{name: "help-log-name-block", command: "download", artifact: "project-1.0-py3-none-any.whl", outcome: evaluation.OutcomeBlock, mode: "help-log"},
			} {
				t.Run(test.name, func(t *testing.T) {
					operationManager := manager
					diagnostics := ""
					if test.shim {
						path := filepath.Join(t.TempDir(), alias)
						if err := os.WriteFile(path, []byte(shimFixture), 0700); err != nil {
							t.Fatal(err)
						}
						diagnostics = filepath.Join(t.TempDir(), "diagnostics")
						t.Setenv("SCFW_TEST_PIP_DEBUG_COUNT", diagnostics)
						t.Setenv("SCFW_TEST_PIP_EXECUTABLE", executable)
						selected, err := pip.NewPip(context.Background(), alias, path)
						if err != nil {
							t.Fatal(err)
						}
						operationManager = selected
					}
					t.Setenv("PIP_CACHE_DIR", t.TempDir())
					destination := t.TempDir()
					args := []string{"--disable-pip-version-check", "--log", filepath.Join(t.TempDir(), "pip.log"), "--timeout", "2", test.command, "--no-deps", "--no-build-isolation", "--no-index", "--retries", "0"}
					if test.mode == "help-log" {
						t.Chdir(t.TempDir())
						args[2] = "help"
						upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							t.Error("blocked operation escaped to its original proxy")
							http.Error(w, "unexpected upstream request", http.StatusBadGateway)
						}))
						defer upstream.Close()
						args = append(args, "--proxy", upstream.URL)
					}
					if test.command == "install" {
						args = append(args, "--upgrade", "--target", destination)
					} else if test.command == "download" {
						args = append(args, "--pref", "--dest", destination)
					} else {
						args = append(args, "--pref", "--wheel-dir", destination)
					}
					artifactURL := base + "/packages/" + test.artifact
					cachedBodies := int32(0)
					if test.mode == "cached-inner" || test.mode == "cached-links" {
						document := "/nested.txt"
						if test.mode == "cached-links" {
							document = "/wheelhouse/"
						}
						script := primeCacheFixture
						child := exec.Command("python3", "-c", script, filepath.Join(os.Getenv("PIP_CACHE_DIR"), "http-v2"), base+document, ca)
						if output, err := child.CombinedOutput(); err != nil {
							t.Fatalf("cache prime: %v %s", err, output)
						}
						cachedBodies = nestedBodies.Load() + linksBodies.Load()
						outer := "/requirements.txt"
						if test.mode == "cached-links" {
							outer = "/links-requirements.txt"
						}
						args = append(args, "-r", base+outer)
					} else if test.mode == "redirect-remote" {
						args = append(args, "-r", base+"/original/requirements.txt")
					} else if test.mode == "latin1-remote" {
						args = append(args, "-r", base+"/latin1.txt")
					} else if test.mode == "quoted-remote" {
						args = append(args, "-r", base+"/quoted.txt")
					} else if test.mode == "gzip-remote" {
						args = append(args, "-r", base+"/requirements.gz")
					} else if test.mode == "gzip-links" {
						args = append(args, "--find-links", base+"/wheelhouse.gz", "project==1.0")
					} else if test.mode == "remote" {
						args = append(args, "-r", base+"/requirements.txt")
					} else if test.mode == "links" {
						args = append(args, "--find-links", base+"/wheelhouse/", "project==1.0")
					} else if test.mode == "local-links" {
						listing := filepath.Join(t.TempDir(), "index.html")
						if err := os.WriteFile(listing, []byte(fmt.Sprintf(localLinksFixture, artifactURL)), 0600); err != nil {
							t.Fatal(err)
						}
						args = append(args, "--find-links", listing, "project==1.0")
					} else if test.mode == "index" {
						for i, arg := range args {
							if arg == "--no-index" {
								args = append(args[:i], args[i+1:]...)
								break
							}
						}
						args = append(args, "-i", base+"/private-index/", "project==1.0")
					} else if test.requirements {
						requirements := filepath.Join(t.TempDir(), "requirements.txt")
						if err := os.WriteFile(requirements, []byte(fmt.Sprintf(directRequirements, artifactURL)), 0600); err != nil {
							t.Fatal(err)
						}
						args = append(args, "-r", requirements)
					} else {
						args = append(args, artifactURL)
					}
					if test.isolated {
						args = append([]string{"--isolated", "--cert", ca}, args...)
					}
					var calls atomic.Int32
					var details bytes.Buffer
					handler := newTestPyPIController(context.Background(), time.Now(), args, alias, operationManager.Executable(), "", proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
						calls.Add(1)
						if interactive {
							t.Error("proxy evaluation must not prompt")
						}
						for target := range targets.Items() {
							if strings.Contains(target.Source, "secret") {
								t.Error("credential leaked into evaluation")
							}
						}
						return evaluation.ScfwPolicyEvaluationReport{Outcome: test.outcome}, nil
					}), nopReporter{}, &details)
					var certPath, proxyURL string
					classifierOptions, err := operationManager.PyPIClassifierOptions(args)
					if err != nil {
						t.Fatal(err)
					}
					controller, err := configureTestPyPIController(handler, classifierOptions)
					if err != nil {
						t.Fatal(err)
					}
					wrapped := func(ctx context.Context, options proxy.Options) proxy.Options {
						// Use observed upload dates where available; avoid public metadata calls.
						options = controller(ctx, options)
						handler.resolveDate = func(context.Context, string, string, string) (time.Time, error) {
							return time.Now(), nil
						}
						return options
					}
					runner := capturingPipRunner{Pip: operationManager, capture: func(config proxy.ClientConfig) { certPath = config.CACertificatePath; proxyURL = config.URL }}
					beforeFetch := artifacts.Load()
					commandErr, setupErr := runThroughProxy(context.Background(), runner, args, wrapped)
					if setupErr != nil {
						t.Fatal(setupErr)
					}
					if test.outcome == evaluation.OutcomeBlock {
						if commandErr == nil {
							t.Fatal("blocked artifact succeeded")
						}
						if artifacts.Load() != beforeFetch {
							t.Fatal("blocked artifact reached the registry")
						}
					} else if commandErr != nil {
						t.Fatal(commandErr)
					}
					if test.name == "download-requirements" {
						before := artifacts.Load()
						cachedErr, cachedSetup := runThroughProxy(context.Background(), runner, args, wrapped)
						if cachedErr != nil || cachedSetup != nil {
							t.Fatalf("cached download failed: %v / %v", cachedErr, cachedSetup)
						}
						if artifacts.Load() != before {
							t.Fatal("pip did not reuse its downloaded artifact")
						}
					}
					if (test.mode == "cached-inner" || test.mode == "cached-links") && nestedBodies.Load()+linksBodies.Load() != cachedBodies {
						t.Fatal("pip fetched a discovery body instead of reusing its warm cache")
					}
					if calls.Load() != 1 {
						t.Fatalf("evaluations=%d, want 1", calls.Load())
					}
					if test.shim {
						data, err := os.ReadFile(diagnostics)
						if err != nil || string(data) != "debug\n" {
							t.Fatalf("diagnostic calls=%q error=%v, want one", data, err)
						}
					}
					if test.outcome == evaluation.OutcomeWarn && (!strings.Contains(details.String(), "WARN") || strings.Contains(details.String(), "Proceed")) {
						t.Fatalf("unexpected warning: %s", details.String())
					}
					if _, err := os.Stat(certPath); !os.IsNotExist(err) {
						t.Fatal("invocation CA was not removed")
					}
					client := http.Client{Timeout: time.Second}
					if _, err := client.Get(proxyURL); err == nil {
						t.Fatal("proxy still listening")
					}
				})
			}
		})
	}
}

type capturingPipRunner struct {
	pip.Pip
	capture func(proxy.ClientConfig)
}

func (r capturingPipRunner) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	r.capture(config)
	return r.Pip.ProxyCommand(ctx, args, config)
}

func TestPipPreservesAuthenticatedUpstream(t *testing.T) {
	executable, err := exec.LookPath("pip3")
	if err != nil {
		t.Skip("pip3 required")
	}
	wheel := pipWheel(t)
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var hits atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy:secret")) {
					http.Error(w, "proxy auth missing", 407)
					return
				}
				user, password, ok := r.BasicAuth()
				if !ok || user != "private" || password != "secret" {
					http.Error(w, "index auth missing", 401)
					return
				}
				hits.Add(1)
				_, _ = w.Write(wheel)
			})
			upstream := httptest.NewUnstartedServer(handler)
			if scheme == "https" {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			defer upstream.Close()
			for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CLIENT_CERT"} {
				t.Setenv(key, "")
			}
			t.Setenv("PIP_CONFIG_FILE", os.DevNull)
			t.Setenv("PIP_CACHE_DIR", t.TempDir())
			t.Setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
			proxyURL := strings.Replace(upstream.URL, "://", "://proxy:secret@", 1)
			t.Setenv("PIP_PROXY", "http://overridden.invalid")
			if scheme == "https" {
				path := filepath.Join(t.TempDir(), "upstream.pem")
				if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PIP_CERT", path)
			}
			manager, err := pip.NewPip(context.Background(), "pip3", executable)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"download", "--no-deps", "--no-index", "--dest", t.TempDir(), "http://private:secret@registry.example/project-1.0-py3-none-any.whl"}
			if scheme == "http" {
				args = append([]string{"--proxy", proxyURL}, args...)
			} else {
				args = append(args, "--proxy="+proxyURL)
			}
			options, err := manager.ProxyOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			if options.Upstream.HTTPProxy != proxyURL || options.Upstream.HTTPSProxy != proxyURL {
				t.Fatal("effective proxy URL was changed")
			}
			commandErr, setupErr := runThroughProxy(context.Background(), manager, args, nil)
			if setupErr != nil || commandErr != nil {
				t.Fatalf("run: %v / %v", setupErr, commandErr)
			}
			if hits.Load() != 1 {
				t.Fatalf("upstream hits=%d", hits.Load())
			}
		})
	}
}

func TestPipVCSUsesInvocationTrust(t *testing.T) {
	executable, err := exec.LookPath("pip3")
	if err != nil {
		t.Skip("pip3 required")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git required")
	}
	directory := t.TempDir()
	reader, err := gzip.NewReader(bytes.NewReader(pipSdist(t)))
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
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, filepath.Base(header.Name)), data, 0600); err != nil {
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
			http.Error(w, "auth required", 401)
			return
		}
		requests.Add(1)
		files.ServeHTTP(w, r)
	}))
	defer registry.Close()
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "PIP_PROXY", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CLIENT_CERT"} {
		t.Setenv(key, "")
	}
	t.Setenv("NO_PROXY", "*")
	t.Setenv("PIP_CONFIG_FILE", os.DevNull)
	t.Setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
	t.Setenv("PIP_CACHE_DIR", t.TempDir())
	certificate := filepath.Join(t.TempDir(), "git-ca.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", certificate)
	manager, err := pip.NewPip(context.Background(), "pip3", executable)
	if err != nil {
		t.Fatal(err)
	}
	vcsURL := "git+" + strings.Replace(registry.URL, "https://", "https://private:secret@", 1)
	args := []string{"wheel", "--no-deps", "--no-build-isolation", "--no-index", "--wheel-dir", t.TempDir(), vcsURL}
	commandErr, setupErr := runThroughProxy(context.Background(), manager, args, nil)
	if setupErr != nil || commandErr != nil {
		t.Fatalf("VCS run: %v / %v", setupErr, commandErr)
	}
	if requests.Load() == 0 {
		t.Fatal("VCS dependency did not reach authenticated origin")
	}
	if os.Getenv("GIT_SSL_CAINFO") != certificate {
		t.Fatal("parent Git trust changed")
	}
}

func TestPyPIControllerEvaluatesUnconfiguredArtifactURLs(t *testing.T) {
	var calls atomic.Int32
	evaluator := newTestPyPIController(context.Background(), time.Now(), nil, "pip", "pip", "", proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		calls.Add(1)
		return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
	}), nopReporter{}, io.Discard)
	controller, err := configureTestPyPIController(evaluator, pypi.RequestClassifierOptions{})
	if err != nil {
		t.Fatal(err)
	}
	options := controller(context.Background(), proxy.Options{})
	evaluator.resolveDate = func(context.Context, string, string, string) (time.Time, error) {
		return time.Now(), nil
	}
	artifact, err := url.Parse("https://private.example/project-1.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := options.RequestHooks[0](context.Background(), proxy.Request{Method: http.MethodGet, URL: *artifact}); err == nil {
		t.Fatal("artifact URL without explicit configuration escaped evaluation")
	}
	if calls.Load() != 1 {
		t.Fatalf("evaluations = %d, want 1", calls.Load())
	}
}
