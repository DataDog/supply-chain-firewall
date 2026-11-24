// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
)

// pnpmGitPackage is the name of the git dependency fixture every pnpm git test
// installs.
const pnpmGitPackage = "lab-git-pkg"

// pnpmGitAllowlist returns the pnpm-workspace.yaml content that approves the
// git dependency's build scripts: pnpm 10 reads onlyBuiltDependencies and
// pnpm 11 and 12 allowBuilds, both keyed by the dependency's name, spec and
// commit.
func pnpmGitAllowlist(t *testing.T, major int, spec, sha string) string {
	t.Helper()
	fixture := "pnpm/git-workspace.yaml.tmpl"
	if major == 10 {
		fixture = "pnpm/git-workspace-v10.yaml.tmpl"
	}
	return fmt.Sprintf(readProxyFixture(t, fixture), pnpmGitPackage+"@"+spec+"#"+sha)
}

// newPnpmGitProject isolates pnpm and enters a project that installs spec as a
// git dependency whose build scripts the running pnpm major approves.
func newPnpmGitProject(t *testing.T, registry *npmTestRegistry, major int, spec, sha string) string {
	t.Helper()
	dir := enterPnpmTestProject(t)
	manifest := fmt.Sprintf(readProxyFixture(t, "pnpm/git-project.json.tmpl"), spec)
	writeNpmProject(t, dir, manifest, "registry="+registry.URL+"/\ncafile="+registry.CAPath+"\n")
	if err := os.WriteFile(filepath.Join(dir, "pnpm-workspace.yaml"), []byte(pnpmGitAllowlist(t, major, spec, sha)), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// pnpmProjectFiles snapshots the configuration files a run must not modify.
func pnpmProjectFiles(t *testing.T, dir, gitConfig string) map[string][]byte {
	t.Helper()
	files := map[string]string{
		"pnpm-workspace.yaml": filepath.Join(dir, "pnpm-workspace.yaml"),
		".npmrc":              filepath.Join(dir, ".npmrc"),
		"package.json":        filepath.Join(dir, "package.json"),
		"gitconfig":           gitConfig,
	}
	snapshot := map[string][]byte{}
	for name, path := range files {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		snapshot[name] = data
	}
	return snapshot
}

func assertPnpmFilesUnchanged(t *testing.T, before map[string][]byte, dir, gitConfig string) {
	t.Helper()
	after := pnpmProjectFiles(t, dir, gitConfig)
	for name, data := range before {
		if !bytes.Equal(after[name], data) {
			t.Fatalf("%s changed", name)
		}
	}
}

// assertPnpmGitEvaluation checks one evaluation of the checkout, with the
// redacted remote and commit as the source.
func assertPnpmGitEvaluation(t *testing.T, run pnpmProxyRun, spec, sha string) {
	t.Helper()
	if run.calls != 1 {
		t.Fatalf("evaluator calls = %d, want 1 (sources %v)", run.calls, run.sources)
	}
	if want := strings.TrimPrefix(spec, "git+") + "#" + sha; !slices.Equal(run.sources, []string{want}) {
		t.Fatalf("sources = %v, want [%s]", run.sources, want)
	}
}

func TestPnpmGitDependencyAllowed(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		spec, sha, marker := npmGitDependency(t)
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, spec, sha)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeAllow)
		assertPnpmSucceeded(t, run)
		if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage, "package.json")); err != nil {
			t.Fatalf("git dependency not installed: %v", err)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("approved prepare script did not run: %v", err)
		}
		// pnpm clones a git dependency more than once; each checkout shares one decision.
		assertPnpmGitEvaluation(t, run, spec, sha)
		assertProxyCleaned(t, run.config)
	})
}

func TestPnpmGitDependencyBlocked(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		spec, sha, marker := npmGitDependency(t)
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, spec, sha)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeBlock)
		assertPnpmFailed(t, run)
		if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage)); err == nil {
			t.Fatal("blocked git dependency was installed")
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("blocked git dependency's prepare script ran")
		}
		assertPnpmGitEvaluation(t, run, spec, sha)
	})
}

// pnpm installs a git dependency whose manifest has no version and runs its
// approved build scripts, so the checkout must still be evaluated and can be
// blocked before any of its code runs.
func TestPnpmGitDependencyWithoutVersionIsEvaluated(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		spec, sha, marker := npmGitDependencyFrom(t, "npm/git-package-no-version/package.json")
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, spec, sha)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeBlock)
		assertPnpmFailed(t, run)
		if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage)); err == nil {
			t.Fatal("blocked git dependency was installed")
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("blocked git dependency's prepare script ran")
		}
		assertPnpmGitEvaluation(t, run, spec, sha)
	})
}

func TestPnpmGitDependencyWarnContinues(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		spec, sha, marker := npmGitDependency(t)
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, spec, sha)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeWarn)
		assertPnpmSucceeded(t, run)
		if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage, "package.json")); err != nil {
			t.Fatalf("git dependency not installed: %v", err)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("warned prepare script did not run: %v", err)
		}
	})
}

// pnpmGitOrigin is a git dependency fixture served as a remote.
type pnpmGitOrigin struct {
	spec, sha, caPath, marker string
}

// startPnpmGitHTTPOrigin serves the git dependency fixture over HTTPS through
// git http-backend, the shape pnpm clones from an https remote.
func startPnpmGitHTTPOrigin(t *testing.T, manifest string) pnpmGitOrigin {
	t.Helper()
	spec, sha, marker := npmGitDependencyFrom(t, manifest)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git required for pnpm git dependency tests")
	}
	root := t.TempDir()
	bare := filepath.Join(root, "acme", "lab-repo.git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(git, "clone", "-q", "--bare", strings.TrimPrefix(spec, "git+"), bare).CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, output)
	}
	backend := cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	server := httptest.NewTLSServer(http.HandlerFunc(backend.ServeHTTP))
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "origin-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return pnpmGitOrigin{spec: "git+" + server.URL + "/acme/lab-repo.git", sha: sha, caPath: caPath, marker: marker}
}

// pnpmUserGitConfig writes the user's global Git configuration with the given
// https remote CA, upstream proxy and ssh command, and selects it.
func pnpmUserGitConfig(t *testing.T, caPath, proxyURL, sshCommand string) string {
	t.Helper()
	var config strings.Builder
	if caPath != "" {
		fmt.Fprintf(&config, "[http]\n\tsslCAInfo = %s\n", caPath)
	}
	if proxyURL != "" {
		fmt.Fprintf(&config, "[http]\n\tproxy = %s\n", proxyURL)
	}
	if sshCommand != "" {
		fmt.Fprintf(&config, "[core]\n\tsshCommand = %s\n", sshCommand)
	}
	path := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(path, []byte(config.String()), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", path)
	return path
}

// The user's Git CA and proxy settings apply to an https remote: pnpm's Git
// traffic leaves through the user's upstream proxy, verified by the user's
// CA, and the checkout is still evaluated.
func TestPnpmGitDependencyOverHTTPSUsesUserGitSettings(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		origin := startPnpmGitHTTPOrigin(t, "npm/git-package/package.json")
		var hits atomic.Int32
		upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &hits})
		gitConfig := pnpmUserGitConfig(t, origin.caPath, strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1), "")
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, origin.spec, origin.sha)
		files := pnpmProjectFiles(t, dir, gitConfig)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeAllow)
		assertPnpmSucceeded(t, run)
		if hits.Load() == 0 {
			t.Fatal("Git traffic did not traverse the user's upstream proxy")
		}
		assertPnpmGitEvaluation(t, run, origin.spec, origin.sha)
		assertPnpmFilesUnchanged(t, files, dir, gitConfig)
		assertProxyCleaned(t, run.config)
	})
}

func TestPnpmGitDependencyOverHTTPSBlocked(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		origin := startPnpmGitHTTPOrigin(t, "npm/git-package/package.json")
		marker := origin.marker
		gitConfig := pnpmUserGitConfig(t, origin.caPath, "", "")
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, origin.spec, origin.sha)
		files := pnpmProjectFiles(t, dir, gitConfig)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeBlock)
		assertPnpmFailed(t, run)
		if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage)); err == nil {
			t.Fatal("blocked git dependency was installed")
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("blocked git dependency's prepare script ran")
		}
		assertPnpmGitEvaluation(t, run, origin.spec, origin.sha)
		assertPnpmFilesUnchanged(t, files, dir, gitConfig)
	})
}

// GIT_SSL_NO_VERIFY cannot send pnpm's Git traffic around SCFW: the variable
// is removed from pnpm's children, so the traffic still crosses the Git
// client and the checkout is still evaluated and blockable. The user's own
// setting keeps applying to SCFW's outbound connection, as for the other
// adapters.
func TestPnpmGitDependencyOverHTTPSWithoutCA(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		origin := startPnpmGitHTTPOrigin(t, "npm/git-package/package.json")
		pnpmUserGitConfig(t, "", "", "")
		t.Setenv("GIT_SSL_NO_VERIFY", "1")
		dir := newPnpmGitProject(t, startNpmRegistry(t), major, origin.spec, origin.sha)
		run := runPnpmGitThroughProxy(t, executable, []string{"install"}, evaluation.OutcomeBlock)
		assertPnpmFailed(t, run)
		if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage)); err == nil {
			t.Fatal("blocked git dependency was installed")
		}
		if _, err := os.Stat(origin.marker); err == nil {
			t.Fatal("blocked git dependency's prepare script ran")
		}
		assertPnpmGitEvaluation(t, run, origin.spec, origin.sha)
	})
}

// startPnpmGitSSHOrigin makes the git dependency fixture reachable through a
// git+ssh:// remote: Git asks the user's ssh command, here the fake testdata
// script, to run git-upload-pack against a local bare repository.
func startPnpmGitSSHOrigin(t *testing.T) pnpmGitOrigin {
	t.Helper()
	spec, sha, marker := npmGitDependencyFrom(t, "npm/git-package/package.json")
	root := t.TempDir()
	bare := filepath.Join(root, "acme", "lab-repo.git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "clone", "-q", "--bare", strings.TrimPrefix(spec, "git+"), bare).CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, output)
	}
	// The fixture is copied so it can run from the isolated project directory.
	script := filepath.Join(t.TempDir(), "git-ssh.sh")
	if err := os.WriteFile(script, []byte(readProxyFixture(t, "pnpm/git-ssh.sh")), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCFW_TEST_SSH_ROOT", root)
	pnpmUserGitConfig(t, "", "", script)
	return pnpmGitOrigin{spec: "git+ssh://git@localhost/acme/lab-repo.git", sha: sha, marker: marker}
}

func TestPnpmGitDependencyOverSSH(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		for _, test := range []struct {
			name    string
			outcome evaluation.Outcome
			blocked bool
		}{
			{name: "allowed", outcome: evaluation.OutcomeAllow},
			{name: "blocked", outcome: evaluation.OutcomeBlock, blocked: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				origin := startPnpmGitSSHOrigin(t)
				marker := origin.marker
				gitConfig := os.Getenv("GIT_CONFIG_GLOBAL")
				dir := newPnpmGitProject(t, startNpmRegistry(t), major, origin.spec, origin.sha)
				files := pnpmProjectFiles(t, dir, gitConfig)
				run := runPnpmGitThroughProxy(t, executable, []string{"install"}, test.outcome)
				if test.blocked {
					assertPnpmFailed(t, run)
					if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage)); err == nil {
						t.Fatal("blocked git dependency was installed")
					}
					if _, err := os.Stat(marker); err == nil {
						t.Fatal("blocked git dependency's prepare script ran")
					}
				} else {
					assertPnpmSucceeded(t, run)
					if _, err := os.Stat(filepath.Join(dir, "node_modules", pnpmGitPackage, "package.json")); err != nil {
						t.Fatalf("git dependency not installed: %v", err)
					}
					if _, err := os.Stat(marker); err != nil {
						t.Fatalf("approved prepare script did not run: %v", err)
					}
				}
				// pnpm normalizes the ssh user out of the origin it sets.
				if run.calls != 1 {
					t.Fatalf("evaluator calls = %d, want 1 (sources %v)", run.calls, run.sources)
				}
				if want := "ssh://localhost/acme/lab-repo.git#" + origin.sha; !slices.Equal(run.sources, []string{want}) {
					t.Fatalf("sources = %v, want [%s]", run.sources, want)
				}
				assertPnpmFilesUnchanged(t, files, dir, gitConfig)
				assertProxyCleaned(t, run.config)
			})
		}
	})
}
