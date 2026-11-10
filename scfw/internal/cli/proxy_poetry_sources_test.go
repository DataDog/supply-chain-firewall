// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPoetrySymlinkProjectPreservesLocalTLS(t *testing.T) {
	manager := poetryForProxyTest(t)
	wheel := pypiWheel(t)
	simple := readProxyFixture(t, "poetry/simple.html")
	var downloads atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".whl") {
			downloads.Add(1)
			_, _ = w.Write(wheel)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, simple)
	}))
	defer origin.Close()
	for _, projectOption := range []bool{false, true} {
		for _, proxied := range []bool{false, true} {
			t.Run(fmt.Sprintf("project-option=%t/proxied=%t", projectOption, proxied), func(t *testing.T) {
				root := t.TempDir()
				physical := filepath.Join(root, "real")
				work := filepath.Join(physical, "work")
				if err := os.MkdirAll(work, 0700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(root, "link")
				if err := os.Symlink(work, link); err != nil {
					t.Fatal(err)
				}
				ca := filepath.Join(root, "origin.pem")
				poetryTestFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})))
				manifest := fmt.Sprintf(readProxyFixture(t, "poetry/pyproject.toml.tmpl"), `project = "1.0"`, "", origin.URL, "primary")
				configuration := fmt.Sprintf(readProxyFixture(t, "poetry/source-tls.toml.tmpl"), strconv.Quote(ca), strconv.Quote(""))
				decoy := fmt.Sprintf(readProxyFixture(t, "poetry/source-tls.toml.tmpl"), strconv.Quote("/missing/decoy.pem"), strconv.Quote(""))
				paths := map[string]string{
					filepath.Join(root, "pyproject.toml"):     manifest,
					filepath.Join(root, "poetry.toml"):        decoy,
					filepath.Join(physical, "pyproject.toml"): manifest,
					filepath.Join(physical, "poetry.toml"):    configuration,
				}
				for path, content := range paths {
					poetryTestFile(t, path, content)
				}
				t.Setenv("POETRY_CACHE_DIR", filepath.Join(root, "cache"))
				args := []string{"--directory", link + "/.."}
				if projectOption {
					args = []string{"--directory", link, "--project", ".."}
				}
				args = append(args, "--no-interaction", "lock")
				before := downloads.Load()
				if proxied {
					runner := &capturingPoetryRunner{Poetry: manager}
					commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
					if commandErr != nil || setupErr != nil {
						t.Fatalf("proxied project TLS: %v / %v", commandErr, setupErr)
					}
					assertProxyCleaned(t, runner.config)
				} else if err := manager.RunCommand(context.Background(), args); err != nil {
					t.Fatalf("direct project TLS: %v", err)
				}
				if downloads.Load() == before {
					t.Fatal("selected project did not download a distribution")
				}
				for path, content := range paths {
					actual, err := os.ReadFile(path)
					if err != nil || string(actual) != content {
						t.Fatal("project configuration changed")
					}
				}
			})
		}
	}
}

func TestPoetryConfiguredRepositoriesPreserveTLS(t *testing.T) {
	manager := poetryForProxyTest(t)
	wheel := pypiWheel(t)
	for _, test := range []struct {
		name                  string
		environment, insecure bool
	}{
		{name: "private"}, {name: "Private"}, {name: "private", environment: true}, {name: "private", insecure: true},
	} {
		t.Run(fmt.Sprintf("%s/environment=%t/insecure=%t", test.name, test.environment, test.insecure), func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				username, password, ok := r.BasicAuth()
				if !ok || username != "private" || password != "secret" {
					http.Error(w, "authentication required", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write(wheel)
			}))
			defer origin.Close()
			config := t.TempDir()
			ca := filepath.Join(config, "origin.pem")
			poetryTestFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})))
			cert := strconv.Quote(ca)
			if test.insecure {
				cert = "false"
			}
			address := origin.URL
			if test.environment {
				address = "https://unselected.example/"
				t.Setenv("POETRY_REPOSITORIES_PRIVATE_URL", origin.URL)
			}
			configuration := fmt.Sprintf(readProxyFixture(t, "poetry/repository-tls.toml.tmpl"), test.name, strconv.Quote(address), test.name, cert)
			path := filepath.Join(config, "config.toml")
			poetryTestFile(t, path, configuration)
			t.Setenv("POETRY_CONFIG_DIR", config)
			for _, proxied := range []bool{false, true} {
				root := t.TempDir()
				t.Setenv("POETRY_CACHE_DIR", filepath.Join(root, "cache"))
				poetryTestFile(t, filepath.Join(root, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
				args := []string{"--directory", root, "--no-interaction", "add", "--lock", origin.URL + "/project-1.0-py3-none-any.whl"}
				if !proxied {
					if err := manager.RunCommand(context.Background(), args); err != nil {
						t.Fatalf("direct Poetry: %v", err)
					}
					continue
				}
				runner := &capturingPoetryRunner{Poetry: manager}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
				if commandErr != nil || setupErr != nil {
					t.Fatalf("proxied Poetry: %v / %v", commandErr, setupErr)
				}
				assertProxyCleaned(t, runner.config)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != configuration {
				t.Fatal("configured repository was modified")
			}
		})
	}
}

func TestPoetryRunPreservesChildOptions(t *testing.T) {
	manager := poetryForProxyTest(t)
	root := t.TempDir()
	poetryTestFile(t, filepath.Join(root, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
	poetryTestFile(t, filepath.Join(root, "child-options.py"), readProxyFixture(t, "poetry/child-options.py"))
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	poetryTestFile(t, filepath.Join(child, "pyproject.toml"), readProxyFixture(t, "poetry/invalid.lock"))
	t.Chdir(root)
	for _, prefix := range [][]string{{"run"}, {"--directory", root, "run"}, {"run", "--directory", root}} {
		args := append(append([]string{}, prefix...), "python", filepath.Join(root, "child-options.py"), "-P", "child", "--project=child", "-Cchild", "--directory", "child")
		output := filepath.Join(root, "child-output.json")
		t.Setenv("SCFW_TEST_CHILD_OUTPUT", output)
		if err := manager.RunCommand(context.Background(), args); err != nil {
			t.Fatalf("direct Poetry: %v", err)
		}
		expected, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(output); err != nil {
			t.Fatal(err)
		}
		runner := &capturingPoetryRunner{Poetry: manager}
		commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
		if commandErr != nil || setupErr != nil {
			t.Fatalf("proxied child options: %v / %v", commandErr, setupErr)
		}
		actual, err := os.ReadFile(output)
		if err != nil || string(actual) != string(expected) {
			t.Fatalf("child arguments or working directory changed: %s / %s / %v", actual, expected, err)
		}
		assertProxyCleaned(t, runner.config)
	}
}

func TestPoetryHTTPSProxyPreservesDisabledVerification(t *testing.T) {
	manager := poetryForProxyTest(t)
	wheel := pypiWheel(t)
	simple := readProxyFixture(t, "poetry/simple.html")
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".whl") {
			_, _ = w.Write(wheel)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, simple)
	}))
	defer origin.Close()
	var hits atomic.Int32
	upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", tls: &tls.Config{MinVersion: tls.VersionTLS12}, hits: &hits})
	t.Setenv("https_proxy", strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1))
	for _, proxied := range []bool{false, true} {
		root := t.TempDir()
		t.Setenv("POETRY_CACHE_DIR", filepath.Join(root, "cache"))
		poetryTestFile(t, filepath.Join(root, "pyproject.toml"), fmt.Sprintf(readProxyFixture(t, "poetry/pyproject.toml.tmpl"), `project = "1.0"`, "", origin.URL, "primary"))
		poetryTestFile(t, filepath.Join(root, "poetry.toml"), fmt.Sprintf(readProxyFixture(t, "poetry/source-tls.toml.tmpl"), "false", strconv.Quote("")))
		args := []string{"--directory", root, "--no-interaction", "lock"}
		if !proxied {
			if err := manager.RunCommand(context.Background(), args); err != nil {
				t.Fatalf("direct Poetry: %v", err)
			}
			continue
		}
		runner := &capturingPoetryRunner{Poetry: manager}
		before := hits.Load()
		commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
		if commandErr != nil || setupErr != nil {
			t.Fatalf("proxied HTTPS upstream: %v / %v", commandErr, setupErr)
		}
		if hits.Load() == before {
			t.Fatal("HTTPS upstream proxy was not followed")
		}
		assertProxyCleaned(t, runner.config)
	}
}
