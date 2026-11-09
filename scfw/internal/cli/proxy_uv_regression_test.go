// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/uv"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func uvRegressionPolicy(t *testing.T, manager uv.UV, args []string, calls *atomic.Int32, block bool) proxyHookConfigurer {
	t.Helper()
	return func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
		classifier, err := manager.PyPIClassifierOptions(args)
		if err != nil {
			return nil, err
		}
		hook, err := pypi.NewProxyHook(ctx, pypi.ProxyHookOptions{
			Client: client, ClassifierOptions: classifier,
			ResolvePublishDate: func(context.Context, string, string, string) (time.Time, error) { return time.Unix(1, 0), nil },
			EvaluatePackage: func(_ context.Context, pkg pm.Package, _ error) error {
				calls.Add(1)
				if pkg.Name != "project" || pkg.Version != "1.0" {
					t.Errorf("unexpected package: %+v", pkg)
				}
				if block {
					return proxy.ErrResponseRejected
				}
				return nil
			},
		})
		return []proxy.RequestHook{hook}, err
	}
}

func TestUVOpaqueDirectDownloads(t *testing.T) {
	executable := uvTestEnvironment(t)
	archive := pypiSdist(t)
	script := readProxyFixture(t, "uv/direct-script.py.tmpl")
	project := uvConfigurationFixture(t, "direct-project")
	requirements := readProxyFixture(t, "uv/requirements.txt.tmpl")
	workspace := uvConfigurationFixture(t, "virtual-workspace")
	local := uvConfigurationFixture(t, "local-dependency")
	for _, mediaType := range []string{"text/plain", "text/html", "application/json"} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect.tar.gz" {
				http.Redirect(w, r, "/opaque?token=secret", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", mediaType)
			http.ServeContent(w, r, "download.tar.gz", time.Time{}, bytes.NewReader(archive))
		}))
		t.Cleanup(origin.Close)
		address := origin.URL + "/download.tar.gz"
		for _, mode := range []string{"bare", "named", "redirect", "with", "with-comma", "script", "project", "environment", "requirements", "pip-sync", "stdin", "workspace", "local"} {
			for _, block := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/block=%v", mediaType, mode, block), func(t *testing.T) {
					t.Chdir(t.TempDir())
					t.Setenv("UV_CACHE_DIR", t.TempDir())
					marker := filepath.Join(t.TempDir(), "backend-executed")
					t.Setenv("SCFW_TEST_BACKEND_MARKER", marker)
					args := []string{"--no-config", "pip", "install", "--no-deps", "--no-build-isolation", "--target", t.TempDir()}
					switch mode {
					case "bare":
						args = append(args, address)
					case "redirect":
						args = append(args, origin.URL+"/redirect.tar.gz")
					case "named":
						args = append(args, "project @ "+address)
					case "with", "with-comma":
						args = []string{"--no-config", "run", "--no-build-isolation", "--with", "project @ " + address, "python", "-c", "import importlib.metadata; assert importlib.metadata.version('project') == '1.0'"}
						if mode == "with-comma" {
							args[4] += ", project @ " + address
						}
					case "script":
						if err := os.WriteFile("script.py", []byte(fmt.Sprintf(script, address)), 0600); err != nil {
							t.Fatal(err)
						}
						args = []string{"--no-config", "run", "--no-build-isolation", "script.py"}
					case "project", "environment", "workspace", "local":
						dependency := address
						if mode == "environment" {
							t.Setenv("SCFW_TEST_SOURCE_URL", address)
							dependency = "${SCFW_TEST_SOURCE_URL}"
						}
						manifest := "pyproject.toml"
						if mode == "workspace" || mode == "local" {
							if err := os.Mkdir("member", 0700); err != nil {
								t.Fatal(err)
							}
							root := workspace
							if mode == "local" {
								root = local
							}
							if err := os.WriteFile(manifest, []byte(root), 0600); err != nil {
								t.Fatal(err)
							}
							manifest = filepath.Join("member", manifest)
						}
						if err := os.WriteFile(manifest, []byte(fmt.Sprintf(project, dependency)), 0600); err != nil {
							t.Fatal(err)
						}
						args = []string{"--no-config", "sync", "--no-build-isolation"}
					case "requirements", "pip-sync", "stdin":
						input := fmt.Sprintf(requirements, address)
						if mode == "stdin" {
							reader, writer, err := os.Pipe()
							if err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
							if _, err := io.WriteString(writer, input); err != nil {
								t.Fatal(err)
							}
							_ = writer.Close()
							original := os.Stdin
							os.Stdin = reader
							defer func() { os.Stdin = original }()
							args = append(args, "-r", "-")
						} else {
							if err := os.WriteFile("requirements.txt", []byte(input), 0600); err != nil {
								t.Fatal(err)
							}
							if mode == "pip-sync" {
								args = []string{"--no-config", "pip", "sync", "--no-build-isolation", "--target", t.TempDir(), "requirements.txt"}
							} else {
								args = append(args, "-r", "requirements.txt")
							}
						}
					}
					manager, err := uv.NewUV(context.Background(), "uv", executable)
					if err != nil {
						t.Fatal(err)
					}
					runner := &capturingUVRunner{UV: manager}
					var calls atomic.Int32
					commandErr, setupErr := runThroughProxy(context.Background(), runner, args, uvRegressionPolicy(t, manager, args, &calls, block))
					if setupErr != nil || (commandErr != nil) != block || calls.Load() == 0 {
						t.Fatalf("opaque source: %v/%v calls=%d", commandErr, setupErr, calls.Load())
					}
					_, markerErr := os.Stat(marker)
					if (block && !os.IsNotExist(markerErr)) || (!block && markerErr != nil) {
						t.Fatalf("build backend execution did not match policy: block=%v, %v", block, markerErr)
					}
					assertUVProxyCleaned(t, runner)
				})
			}
		}
	}
}

func TestUVEffectiveConfigurationRoutes(t *testing.T) {
	executable := uvTestEnvironment(t)
	wheel := pypiWheel(t)
	proxyTemplate := uvConfigurationFixture(t, "proxy")
	workspace := uvConfigurationFixture(t, "workspace")
	member := uvConfigurationFixture(t, "member")
	exclusions := uvConfigurationFixture(t, "workspace-exclude")
	memberProxy := uvConfigurationFixture(t, "member-proxy")
	main := readProxyFixture(t, "uv/__main__.py")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "project-1.0-py3-none-any.whl", time.Time{}, bytes.NewReader(wheel))
	}))
	defer origin.Close()
	for _, mode := range []string{"symlink", "symlink-parent", "fallback-directory", "directory-run", "zipapp-run", "workspace", "workspace-exclusion"} {
		for _, block := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/block=%v", mode, block), func(t *testing.T) {
				t.Chdir(t.TempDir())
				t.Setenv("UV_CACHE_DIR", t.TempDir())
				actual := t.TempDir()
				var hits atomic.Int32
				upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "review:secret", hits: &hits})
				address := strings.Replace(upstream.URL, "://", "://review:secret@", 1)
				if err := os.WriteFile(filepath.Join(actual, "uv.toml"), []byte(fmt.Sprintf(proxyTemplate, address)), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"pip", "install", "--no-deps", "--target", t.TempDir(), origin.URL + "/project-1.0-py3-none-any.whl"}
				switch mode {
				case "symlink", "symlink-parent", "fallback-directory":
					nested := filepath.Join(actual, "nested")
					if err := os.Mkdir(nested, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(nested, "link"); err != nil {
						t.Fatal(err)
					}
					path := "link"
					if mode == "symlink-parent" {
						path += "/.."
					}
					if mode == "fallback-directory" {
						t.Setenv("UV_WORKING_DIRECTORY", nested)
					} else {
						args = append([]string{"--directory", path}, args...)
					}
				case "directory-run", "zipapp-run":
					target := filepath.Join(actual, "package")
					if mode == "directory-run" {
						if err := os.Mkdir(target, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(target, "__main__.py"), []byte(main), 0600); err != nil {
							t.Fatal(err)
						}
					} else {
						var buffer bytes.Buffer
						writer := zip.NewWriter(&buffer)
						entry, err := writer.Create("__main__.py")
						if err != nil {
							t.Fatal(err)
						}
						_, _ = entry.Write([]byte(main))
						if err := writer.Close(); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(target, buffer.Bytes(), 0600); err != nil {
							t.Fatal(err)
						}
					}
					args = []string{"run", "--with", origin.URL + "/project-1.0-py3-none-any.whl", target}
				case "workspace", "workspace-exclusion":
					_ = os.Remove(filepath.Join(actual, "uv.toml"))
					rootConfig := fmt.Sprintf(workspace, address)
					memberConfig := member
					path := filepath.Join(actual, "packages", "foo")
					if mode == "workspace-exclusion" {
						rootConfig, memberConfig = exclusions, fmt.Sprintf(memberProxy, address)
						path = filepath.Join(actual, "packages", "nested", "foo")
					}
					if err := os.WriteFile(filepath.Join(actual, "pyproject.toml"), []byte(rootConfig), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(path, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(path, "pyproject.toml"), []byte(memberConfig), 0600); err != nil {
						t.Fatal(err)
					}
					args = append([]string{"--directory", path}, args...)
				}
				manager, err := uv.NewUV(context.Background(), "uv", executable)
				if err != nil {
					t.Fatal(err)
				}
				runner := &capturingUVRunner{UV: manager}
				var calls atomic.Int32
				commandErr, setupErr := runThroughProxy(context.Background(), runner, args, uvRegressionPolicy(t, manager, args, &calls, block))
				if setupErr != nil || (commandErr != nil) != block || calls.Load() == 0 || (!block && hits.Load() == 0) {
					t.Fatalf("routing: %v/%v calls=%d upstream=%d", commandErr, setupErr, calls.Load(), hits.Load())
				}
				assertUVProxyCleaned(t, runner)
			})
		}
	}
}

// UV 0.12+ rejects legacy source formats before downloading. CI pins 0.9.0 in
// a separate step so this regression exercises archive inspection and builds.
func TestUVZstandardDownloads(t *testing.T) {
	executable := uvTestEnvironment(t)
	version, err := exec.Command(executable, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(version), "uv 0.9.") {
		t.Skip("requires uv 0.9.x; CI runs this separately from the current uv suite")
	}
	archive := pypiSdistArchive(t, "zstd")
	simple := readProxyJSONFixture(t, "uv/simple-zstd")
	for _, test := range []struct {
		name, filename, mediaType string
		index                     bool
	}{
		{name: "named", filename: "project-1.0.tar.zst", mediaType: "application/octet-stream"},
		{name: "opaque", filename: "download.tar.zst", mediaType: "text/plain"},
		{name: "redirect", filename: "redirect.tar.zst", mediaType: "text/html"},
		{name: "index", filename: "download.tar.zst", mediaType: "application/octet-stream", index: true},
	} {
		for _, block := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/block=%v", test.name, block), func(t *testing.T) {
				t.Chdir(t.TempDir())
				t.Setenv("UV_CACHE_DIR", t.TempDir())
				marker := filepath.Join(t.TempDir(), "backend-executed")
				t.Setenv("SCFW_TEST_BACKEND_MARKER", marker)
				var downloads atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/simple/project/":
						w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
						_, _ = io.WriteString(w, simple)
						return
					case "/redirect.tar.zst":
						http.Redirect(w, r, "/objects/opaque", http.StatusFound)
						return
					}
					downloads.Add(1)
					w.Header().Set("Content-Type", test.mediaType)
					http.ServeContent(w, r, test.filename, time.Time{}, bytes.NewReader(archive))
				}))
				defer origin.Close()
				args := []string{"--no-config", "pip", "install", "--no-deps", "--no-build-isolation", "--target", t.TempDir()}
				if test.index {
					args = append(args, "--index-url", origin.URL+"/simple/", "project==1.0")
				} else {
					args = append(args, "project @ "+origin.URL+"/"+test.filename)
				}
				manager, err := uv.NewUV(context.Background(), "uv", executable)
				if err != nil {
					t.Fatal(err)
				}
				runner := &capturingUVRunner{UV: manager}
				var calls atomic.Int32
				commandErr, setupErr := runThroughProxy(context.Background(), runner, args, uvRegressionPolicy(t, manager, args, &calls, block))
				if setupErr != nil || (commandErr != nil) != block || calls.Load() == 0 {
					t.Fatalf("Zstandard policy: %v/%v calls=%d", commandErr, setupErr, calls.Load())
				}
				_, markerErr := os.Stat(marker)
				if (block && !os.IsNotExist(markerErr)) || (!block && markerErr != nil) {
					t.Fatalf("build backend execution did not match policy: block=%v, %v", block, markerErr)
				}
				if block && (test.name == "named" || test.index) && downloads.Load() != 0 {
					t.Fatal("identified distribution was downloaded before blocking")
				}
				assertUVProxyCleaned(t, runner)
			})
		}
	}
}
