// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/pip"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestPipOpaqueDownloadsEndToEnd(t *testing.T) {
	requirementsFixture := readProxyFixture(t, "requirements/direct.txt.tmpl")
	for _, alias := range []string{"pip", "pip3"} {
		t.Run(alias, func(t *testing.T) {
			executable, err := exec.LookPath(alias)
			if err != nil {
				t.Skip("pip required for integration tests")
			}
			for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "PIP_PROXY", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CLIENT_CERT", "PIP_TRUSTED_HOST", "PIP_EXTRA_INDEX_URL", "GIT_SSL_CAINFO"} {
				t.Setenv(key, "")
			}
			t.Setenv("PIP_CONFIG_FILE", os.DevNull)
			t.Setenv("NO_PROXY", "*")
			t.Setenv("no_proxy", "*")
			sdist := pypiSdist(t)
			sourceTree := pypiSdist(t, "pyproject.toml", "backend.py")
			for _, test := range []struct {
				name                                      string
				outcome                                   evaluation.Outcome
				requirements, compressed, cached, missing bool
			}{
				{name: "allow", outcome: evaluation.OutcomeAllow},
				{name: "warn requirements", outcome: evaluation.OutcomeWarn, requirements: true},
				{name: "block", outcome: evaluation.OutcomeBlock},
				{name: "block requirements", outcome: evaluation.OutcomeBlock, requirements: true},
				{name: "HTTP compressed", outcome: evaluation.OutcomeAllow, compressed: true},
				{name: "cached block", outcome: evaluation.OutcomeBlock, cached: true},
				{name: "missing metadata", outcome: evaluation.OutcomeAllow, requirements: true, missing: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					spool := t.TempDir()
					workspace := t.TempDir()
					directory := func() string {
						path, err := os.MkdirTemp(workspace, "case-*")
						if err != nil {
							t.Fatal(err)
						}
						return path
					}
					t.Setenv("TMPDIR", spool)
					t.Setenv("PIP_CACHE_DIR", directory())
					marker := filepath.Join(directory(), "backend-executed")
					t.Setenv("SCFW_TEST_BACKEND_MARKER", marker)
					var conditional atomic.Int32
					registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						user, password, ok := r.BasicAuth()
						if !ok || user != "private" || password != "secret" || r.URL.Query().Get("token") != "credential-secret" {
							http.Error(w, "authentication required", http.StatusUnauthorized)
							return
						}
						w.Header().Set("ETag", `"opaque-v1"`)
						w.Header().Set("Cache-Control", "public, max-age=0")
						if test.cached && r.Header.Get("If-None-Match") == `"opaque-v1"` {
							conditional.Add(1)
							w.WriteHeader(http.StatusNotModified)
							return
						}
						w.Header().Set("Content-Type", "application/octet-stream")
						payload := sdist
						if test.missing {
							payload = sourceTree
						}
						if test.compressed {
							w.Header().Set("Content-Encoding", "gzip")
						}
						// The existing sdist is gzip-encoded tar. Pip retains the wire
						// bytes; inspection may decode the HTTP representation only.
						_, _ = w.Write(payload)
					}))
					defer registry.Close()
					ca := filepath.Join(directory(), "registry.pem")
					if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
						t.Fatal(err)
					}
					t.Setenv("PIP_CERT", ca)
					manager, err := pip.NewPip(context.Background(), alias, executable)
					if err != nil {
						t.Fatal(err)
					}
					artifactURL := strings.Replace(registry.URL, "https://", "https://private:secret@", 1) + "/download/abc123?token=credential-secret"
					run := func(outcome evaluation.Outcome) (error, int, string) {
						destination := directory()
						command := "install"
						if test.cached {
							command = "download"
						}
						args := []string{"--disable-pip-version-check", command, "--no-input", "--no-index", "--no-deps", "--no-build-isolation", "--retries", "0", "--timeout", "3"}
						if test.cached {
							args = append(args, "--dest", destination)
						} else {
							args = append(args, "--no-cache-dir", "--target", destination)
						}
						if test.requirements {
							requirements := filepath.Join(directory(), "requirements.txt")
							if err := os.WriteFile(requirements, []byte(fmt.Sprintf(requirementsFixture, artifactURL)), 0600); err != nil {
								t.Fatal(err)
							}
							args = append(args, "-r", requirements)
						} else {
							args = append(args, "project @ "+artifactURL)
						}
						var calls atomic.Int32
						var details bytes.Buffer
						handler := newTestPyPIController(context.Background(), time.Now(), args, alias, manager.Executable(), "", proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
							calls.Add(1)
							if interactive {
								t.Error("opaque download prompted")
							}
							for target := range targets.Items() {
								if target.Name != "project" || target.Version != "1.0" || target.Source != registry.URL+"/download/abc123" {
									t.Errorf("unexpected package identity: %+v", target)
								}
							}
							return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome}, nil
						}), nopReporter{}, &details)
						classifierOptions, err := manager.PyPIClassifierOptions(args)
						if err != nil {
							t.Fatal(err)
						}
						handler.setClassifierOptions(classifierOptions)
						wrapped := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
							handler.packageEvaluator.runContext = ctx
							handler.metadataClient = client
							handler.hook = nil
							handler.resolveDate = func(context.Context, string, string, string) (time.Time, error) { return time.Now(), nil }
							return []proxy.RequestHook{handler.HandleRequest}, nil
						}
						var certificatePath string
						runner := capturingPipRunner{Pip: manager, capture: func(config proxy.ClientConfig) { certificatePath = config.CACertificatePath }}
						commandErr, setupErr := runThroughProxy(context.Background(), runner, args, wrapped)
						if setupErr != nil {
							t.Fatal(setupErr)
						}
						if _, err := os.Stat(filepath.Dir(certificatePath)); !os.IsNotExist(err) {
							t.Fatal("proxy inspection directory was not removed")
						}
						if strings.Contains(details.String(), "secret") {
							t.Fatal("credentials leaked into firewall diagnostics")
						}
						return commandErr, int(calls.Load()), destination
					}
					if test.cached {
						if err, calls, _ := run(evaluation.OutcomeAllow); err != nil || calls != 1 {
							t.Fatalf("cache warmup: calls=%d error=%v", calls, err)
						}
						if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
					}
					err, calls, destination := run(test.outcome)
					blocked := test.outcome == evaluation.OutcomeBlock || test.missing
					if (err != nil) != blocked {
						t.Fatalf("blocked=%v error=%v", blocked, err)
					}
					wantCalls := 1
					if test.missing {
						wantCalls = 0
					}
					if calls != wantCalls {
						t.Fatalf("policy calls=%d want=%d", calls, wantCalls)
					}
					_, markerErr := os.Stat(marker)
					if blocked && !os.IsNotExist(markerErr) {
						t.Fatal("blocked download executed its build backend")
					}
					if !blocked {
						if markerErr != nil {
							t.Fatal("allowed download did not run its build backend")
						}
						metadata, err := os.ReadFile(filepath.Join(destination, "project-1.0.dist-info", "METADATA"))
						if err != nil || !bytes.Contains(metadata, []byte("Version: 1.0")) {
							t.Fatalf("installation failed: %v", err)
						}
					}
					if test.cached && conditional.Load() == 0 {
						t.Fatal("pip did not exercise conditional cache revalidation")
					}
					if entries, err := os.ReadDir(spool); err != nil || len(entries) != 0 {
						t.Fatalf("temporary inspection files leaked: %v %v", entries, err)
					}
				})
			}
		})
	}
}

func TestPipArchiveInterpretationMatchesInstallation(t *testing.T) {
	executable, err := exec.LookPath("pip")
	if err != nil {
		t.Skip("pip required")
	}
	versionOutput, err := exec.CommandContext(t.Context(), executable, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(versionOutput))
	if len(fields) < 2 {
		t.Fatalf("unrecognized pip version: %q", versionOutput)
	}
	version, err := pm.ParseVersion(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("using %s", strings.TrimSpace(string(versionOutput)))
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PIP_PROXY", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CLIENT_CERT", "PIP_TRUSTED_HOST", "PIP_EXTRA_INDEX_URL", "GIT_SSL_CAINFO", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("PIP_CONFIG_FILE", os.DevNull)
	t.Setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
	polyglot := pypiZstandardZIP(t)
	gzipTail := pypiGzipWithZIPTail(t)
	gzipTAR := pypiGzipTARPolyglot(t)
	for _, test := range []struct {
		name, filename, disposition, encoding string
		payload                               []byte
		redirect                              bool
		legacyReject                          bool
	}{
		{name: "zstandard ZIP", filename: "download.zip", payload: polyglot},
		{name: "disposition overrides extension", filename: "download.tar.gz", disposition: `attachment; filename="download.zip"`, payload: polyglot},
		{name: "redirect and disposition", filename: "redirect.tar.gz", disposition: `attachment; filename="download.zip"`, payload: polyglot, redirect: true},
		{name: "raw archive ignores HTTP encoding", filename: "download.zip", encoding: "gzip", payload: polyglot},
		{name: "gzip under TAR filename", filename: "download.tar", payload: pypiSdist(t)},
		{name: "gzip and raw TAR", filename: "download.tar", payload: gzipTAR},
		// Before 26.1, pip selects the ZIP tail, which contains only data.csv.
		// Reject it before policy evaluation because that ZIP has no package metadata.
		{name: "gzip with ZIP tail", filename: "download.tar.gz", payload: gzipTail, legacyReject: true},
	} {
		for _, block := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/block=%v", test.name, block), func(t *testing.T) {
				t.Chdir(t.TempDir())
				marker := filepath.Join(t.TempDir(), "backend-executed")
				t.Setenv("SCFW_TEST_BACKEND_MARKER", marker)
				missingMetadata := test.legacyReject && version.LessThan(pm.Version{Major: 26, Minor: 1})
				rejected := block || missingMetadata
				wantCalls := int32(1)
				if missingMetadata {
					wantCalls = 0
				}
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if test.redirect && r.URL.Path == "/redirect.tar.gz" {
						http.Redirect(w, r, "/opaque", http.StatusFound)
						return
					}
					w.Header().Set("Content-Type", "application/octet-stream")
					if test.disposition != "" {
						w.Header().Set("Content-Disposition", test.disposition)
					}
					if test.encoding != "" {
						w.Header().Set("Content-Encoding", test.encoding)
					}
					http.ServeContent(w, r, test.filename, time.Time{}, bytes.NewReader(test.payload))
				}))
				defer origin.Close()
				target := t.TempDir()
				args := []string{"install", "--disable-pip-version-check", "--no-deps", "--no-build-isolation", "--no-index", "--no-cache-dir", "--retries", "0", "--timeout", "3", "--target", target, "project @ " + origin.URL + "/" + test.filename}
				manager, err := pip.NewPip(context.Background(), "pip", executable)
				if err != nil {
					t.Fatal(err)
				}
				var config proxy.ClientConfig
				runner := capturingPipRunner{Pip: manager, capture: func(value proxy.ClientConfig) { config = value }}
				var calls atomic.Int32
				configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
					options, err := manager.PyPIClassifierOptions(args)
					if err != nil {
						return nil, err
					}
					hook, err := pypi.NewProxyHook(ctx, pypi.ProxyHookOptions{
						Client: client, ClassifierOptions: options,
						ResolvePublishDate: func(context.Context, string, string, string) (time.Time, error) { return time.Unix(1, 0), nil },
						EvaluatePackage: func(_ context.Context, pkg pm.Package, _ error) error {
							calls.Add(1)
							// The polyglots' other TAR interpretation declares "allowed".
							// Policy must evaluate the "project" that pip actually installs.
							if pkg.Name != "project" || pkg.Version != "1.0" {
								t.Errorf("evaluated different package: %+v", pkg)
								return nil
							}
							if block {
								return proxy.ErrResponseRejected
							}
							return nil
						},
					})
					return []proxy.RequestHook{hook}, err
				}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, args, configure)
				if setupErr != nil || (commandErr != nil) != rejected || calls.Load() != wantCalls {
					t.Fatalf("archive policy: %v/%v calls=%d", commandErr, setupErr, calls.Load())
				}
				_, markerErr := os.Stat(marker)
				if (rejected && !os.IsNotExist(markerErr)) || (!rejected && markerErr != nil) {
					t.Fatalf("build execution did not match rejection: rejected=%v error=%v", rejected, markerErr)
				}
				if !rejected {
					if _, err := os.Stat(filepath.Join(target, "project-1.0.dist-info", "METADATA")); err != nil {
						t.Fatal("evaluated package was not installed", err)
					}
				}
				assertProxyCleaned(t, config)
			})
		}
	}
}
