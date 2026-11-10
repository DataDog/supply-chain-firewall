// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestPoetryAutomaticGitFallbackPreservesNativeRouting(t *testing.T) {
	manager := poetryForProxyTest(t)
	for _, agent := range []string{"", "custom-native-agent", "username-scoped-agent"} {
		t.Run("agent="+agent, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "absent-gitconfig"))
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			t.Setenv("GIT_CONFIG_COUNT", "0")
			t.Setenv("GIT_CONFIG_PARAMETERS", "")
			t.Setenv("POETRY_SYSTEM_GIT_CLIENT", "false")
			gitExecutable, err := exec.LookPath("git")
			if err != nil {
				t.Skip("Git required")
			}
			repository := filepath.Join(root, "repository")
			if err := os.Mkdir(repository, 0700); err != nil {
				t.Fatal(err)
			}
			manifest := readProxyFixture(t, "poetry/git-pyproject.toml")
			poetryTestFile(t, filepath.Join(repository, "pyproject.toml"), manifest)
			for _, args := range [][]string{{"init"}, {"add", "."}, {"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=SCFW Test", "-c", "user.email=scfw@example.invalid", "commit", "-m", "fixture"}} {
				child := exec.Command(gitExecutable, args...)
				child.Dir = repository
				if output, err := child.CombinedOutput(); err != nil {
					t.Fatalf("Git fixture: %v %s", err, output)
				}
			}
			backend := cgi.Handler{Path: gitExecutable, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
			var challenges atomic.Int32
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				username, password, ok := r.BasicAuth()
				if !ok || username != "private" || password != "git-secret" {
					challenges.Add(1)
					w.Header().Set("WWW-Authenticate", `Basic realm="SCFW test"`)
					http.Error(w, "credentials required", http.StatusUnauthorized)
					return
				}
				backend.ServeHTTP(w, r)
			}))
			defer origin.Close()
			ca := filepath.Join(root, "git-ca.pem")
			poetryTestFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})))
			// Dulwich uses inherited SSL roots; native Git also has a command-
			// scoped CA. Each must reach the HTTPS origin through its own proxy.
			t.Setenv("SSL_CERT_FILE", ca)
			var nativeHits, bundledHits atomic.Int32
			nativeProxy := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &nativeHits})
			bundledProxy := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &bundledHits})
			authenticated := func(address string) string { return strings.Replace(address, "://", "://proxy:proxy-secret@", 1) }
			t.Setenv("https_proxy", authenticated(bundledProxy.URL))
			helper := filepath.Join(root, "credential-helper.sh")
			poetryTestFile(t, helper, readProxyFixture(t, "poetry/git-credential-helper.sh"))
			if err := os.Chmod(helper, 0700); err != nil {
				t.Fatal(err)
			}
			gitURL := origin.URL
			if agent == "username-scoped-agent" {
				gitURL = strings.Replace(gitURL, "https://", "https://private@", 1)
			}
			values := [][2]string{
				{"http." + gitURL + "/.proxy", authenticated(nativeProxy.URL)},
				{"credential.helper", "!'" + strings.ReplaceAll(helper, "'", "'\\''") + "'"},
				{"http." + gitURL + "/.sslCAInfo", ca},
			}
			if agent != "" {
				values = append(values, [2]string{"http.userAgent", agent})
			}
			if agent == "username-scoped-agent" {
				publicKey, err := x509.MarshalPKIXPublicKey(origin.Certificate().PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(publicKey)
				values = append(values, [2]string{"http.pinnedPubkey", "sha256//" + base64.StdEncoding.EncodeToString(digest[:])})
				// The clone uses origin's proxy; its URL-specific HTTP proxy is
				// a different route and must not win after interception.
				values = append(values, [2]string{"remote.origin.proxy", authenticated(nativeProxy.URL)})
				values[0][1] = authenticated(bundledProxy.URL)
			}
			t.Setenv("GIT_CONFIG_COUNT", fmt.Sprint(len(values)))
			for index, value := range values {
				t.Setenv(fmt.Sprintf("GIT_CONFIG_KEY_%d", index), value[0])
				t.Setenv(fmt.Sprintf("GIT_CONFIG_VALUE_%d", index), value[1])
			}
			project := t.TempDir()
			consumer := strings.Replace(manifest, `name = "git-project"`, `name = "consumer"`, 1)
			poetryTestFile(t, filepath.Join(project, "pyproject.toml"), consumer)
			t.Setenv("POETRY_CACHE_DIR", filepath.Join(project, "cache"))
			runner := &capturingPoetryRunner{Poetry: manager}
			var nativeRequests atomic.Int32
			configure := func(context.Context, *http.Client) ([]proxy.RequestHook, error) {
				return []proxy.RequestHook{func(_ context.Context, request proxy.Request) (proxy.ResponseHook, error) {
					userAgent := request.Header.Get("User-Agent")
					if strings.HasPrefix(userAgent, "git/") || (agent != "" && userAgent == agent) {
						nativeRequests.Add(1)
					}
					return nil, nil
				}}, nil
			}
			before := os.Environ()
			commandErr, setupErr := runThroughProxy(context.Background(), runner, []string{"--directory", project, "--no-interaction", "add", "--lock", "git+" + gitURL + "/repository/.git"}, configure)
			if commandErr != nil || setupErr != nil {
				t.Fatalf("authenticated fallback failed: %v / %v", commandErr, setupErr)
			}
			if nativeRequests.Load() == 0 || nativeHits.Load() == 0 || bundledHits.Load() == 0 || challenges.Load() == 0 {
				t.Fatalf("fallback did not preserve both routes: native requests=%d, native proxy=%d, bundled proxy=%d, challenges=%d", nativeRequests.Load(), nativeHits.Load(), bundledHits.Load(), challenges.Load())
			}
			if strings.Join(before, "\n") != strings.Join(os.Environ(), "\n") {
				t.Fatal("fallback changed parent environment")
			}
			data, err := os.ReadFile(filepath.Join(project, "pyproject.toml"))
			if err != nil || !strings.Contains(string(data), "git-project") {
				t.Fatal("Poetry did not complete the Git add")
			}
			assertProxyCleaned(t, runner.config)
		})
	}
}

func TestPoetryRegeneratesIgnoredLockThroughProxy(t *testing.T) {
	manager := poetryForProxyTest(t)
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprintf("oversized=%t", oversized), func(t *testing.T) {
			root := t.TempDir()
			manifest := readProxyFixture(t, "poetry/git-pyproject.toml")
			poetryTestFile(t, filepath.Join(root, "pyproject.toml"), manifest)
			old := []byte(readProxyFixture(t, "poetry/invalid.lock"))
			if oversized {
				old = bytes.Repeat([]byte("# ignored lock\n"), (4<<20)/14+1)
			}
			lock := filepath.Join(root, "poetry.lock")
			if err := os.WriteFile(lock, old, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--directory", root, "--no-interaction", "lock", "--regenerate"}
			if _, err := manager.PyPIClassifierOptions(args); err != nil {
				t.Fatal(err)
			}
			runner := &capturingPoetryRunner{Poetry: manager}
			commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
			if commandErr != nil || setupErr != nil {
				t.Fatalf("regeneration failed: %v / %v", commandErr, setupErr)
			}
			data, err := os.ReadFile(lock)
			if err != nil || bytes.Equal(data, old) || !bytes.Contains(data, []byte("lock-version")) {
				t.Fatal("Poetry did not regenerate the lockfile")
			}
			data, err = os.ReadFile(filepath.Join(root, "pyproject.toml"))
			if err != nil || string(data) != manifest {
				t.Fatal("regeneration changed the project configuration")
			}
			assertProxyCleaned(t, runner.config)
		})
	}
}

func TestPoetrySymlinkDirectoryPreservesRelativeCA(t *testing.T) {
	manager := poetryForProxyTest(t)
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	wheel := pypiWheel(t)
	var downloads atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write(wheel)
	}))
	defer origin.Close()
	poetryTestFile(t, filepath.Join(real, "ca.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})))
	t.Setenv("REQUESTS_CA_BUNDLE", "../ca.pem")
	for _, proxied := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxied=%t", proxied), func(t *testing.T) {
			project := filepath.Join(real, fmt.Sprintf("project-%t", proxied))
			if err := os.Mkdir(project, 0700); err != nil {
				t.Fatal(err)
			}
			poetryTestFile(t, filepath.Join(project, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
			link := filepath.Join(root, fmt.Sprintf("linked-%t", proxied))
			if err := os.Symlink(project, link); err != nil {
				t.Fatal(err)
			}
			t.Setenv("POETRY_CACHE_DIR", t.TempDir())
			args := []string{"--directory", link, "--no-interaction", "add", "--lock", origin.URL + "/project-1.0-py3-none-any.whl"}
			before := downloads.Load()
			if proxied {
				runner := &capturingPoetryRunner{Poetry: manager}
				commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
				if commandErr != nil || setupErr != nil {
					t.Fatalf("proxied relative CA: %v / %v", commandErr, setupErr)
				}
				assertProxyCleaned(t, runner.config)
			} else if err := manager.RunCommand(context.Background(), args); err != nil {
				t.Fatalf("direct relative CA: %v", err)
			}
			if downloads.Load() == before {
				t.Fatal("relative CA test did not download a distribution")
			}
		})
	}
}
