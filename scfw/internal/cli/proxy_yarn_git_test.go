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
	"net/http/cgi"
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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/githook"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/yarn"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// yarnGitRemote serves a bare repository built from manifest over transport
// ("https" or "ssh"). It returns the Yarn dependency, the remote SCFW reports,
// the commit, the prepare marker, and for https the origin's CA, which the
// caller trusts through GIT_SSL_CAINFO once the project is set up.
func yarnGitRemote(t *testing.T, transport, manifest string) (dependency, remote, sha, marker, ca string) {
	t.Helper()
	spec, sha, marker := npmGitDependencyFrom(t, manifest)
	root := t.TempDir()
	bare := filepath.Join(root, "lab.git")
	if output, err := exec.Command("git", "clone", "-q", "--bare", strings.TrimPrefix(spec, "git+file://"), bare).CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, output)
	}
	if transport == "ssh" {
		ssh, err := filepath.Abs(filepath.Join("testdata", "yarn", "fake-ssh.sh"))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("GIT_SSH_COMMAND", ssh)
		return "git+ssh://git@localhost" + bare, "ssh://localhost" + bare, sha, marker, ""
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	backend := cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	origin := httptest.NewTLSServer(&backend)
	t.Cleanup(origin.Close)
	ca = filepath.Join(root, "origin-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return "git+" + origin.URL + "/lab.git", origin.URL + "/lab.git", sha, marker, ca
}

// runYarnGitThroughProxy runs Yarn with SCFW's git hooks, as scfw run does.
func runYarnGitThroughProxy(t *testing.T, executable string, args []string, outcome evaluation.Outcome) yarnProxyRun {
	t.Helper()
	return runYarnGitThroughProxyWith(t, executable, args, func(pm.Package) evaluation.Outcome { return outcome })
}

func runYarnGitThroughProxyWith(t *testing.T, executable string, args []string, outcome func(pm.Package) evaluation.Outcome) yarnProxyRun {
	t.Helper()
	manager, err := yarn.NewYarn(context.Background(), "yarn", executable)
	if err != nil {
		t.Fatal(err)
	}
	var run yarnProxyRun
	var calls atomic.Int32
	var details bytes.Buffer
	evaluator := proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		calls.Add(1)
		result := evaluation.OutcomeAllow
		for target := range targets.Items() {
			run.sources = append(run.sources, target.Source)
			result = outcome(target)
		}
		return evaluation.ScfwPolicyEvaluationReport{Outcome: result}, nil
	})
	var decide githook.Decide
	configure := func(ctx context.Context, client *http.Client) ([]proxy.RequestHook, error) {
		packageEvaluator := newProxyPackageEvaluator(ctx, time.Now(), append([]string{"yarn"}, args...), "yarn", manager.Executable(), "", evaluator, nopReporter{}, &details)
		decide = yarnGitCheckoutPolicy(packageEvaluator.evaluatePackage)
		hook, err := newNpmProxyHook(ctx, manager, args, client, packageEvaluator.evaluatePackage)
		return []proxy.RequestHook{hook}, err
	}
	runner := capturingYarnRunner{Yarn: manager, capture: func(config proxy.ClientConfig) { run.config = config }}
	hooked := &gitHookRunner{ProxyRunner: runner, executable: os.Args[0], decide: &decide, archives: true}
	run.commandErr, run.setupErr = runThroughProxy(context.Background(), hooked, args, configure)
	hooked.Close()
	run.calls, run.details = calls.Load(), details.String()
	return run
}

// newYarnGitProject enters a project for the Yarn generation, whose rc file
// the caller compares after the run.
func newYarnGitProject(t *testing.T, generation string) (dir, rcName, rc string) {
	t.Helper()
	registry := startNpmRegistry(t)
	if generation == "classic" {
		rc = classicYarnrc(registry, "")
		return newYarnTestProject(t, ".yarnrc", rc), ".yarnrc", rc
	}
	// Yarn 4.10 and later fetch only the git repositories a project approves.
	rc = berryYarnrc(registry, "nodeLinker: node-modules\napprovedGitRepositories:\n  - \"**\"\n")
	return newBerryTestProject(t, rc), ".yarnrc.yml", rc
}

func TestYarnGitDependencies(t *testing.T) {
	for _, generation := range []string{"classic", "berry"} {
		variable := map[string]string{"classic": "SCFW_TEST_YARN_CLASSIC", "berry": "SCFW_TEST_YARN_BERRY"}[generation]
		for _, transport := range []string{"https", "ssh"} {
			for _, test := range []struct {
				name, manifest string
				outcome        evaluation.Outcome
				failed         bool
			}{
				{name: "allowed", manifest: "yarn/git-package/package.json", outcome: evaluation.OutcomeAllow},
				{name: "blocked", manifest: "yarn/git-package/package.json", outcome: evaluation.OutcomeBlock, failed: true},
				// Yarn 4 installs a manifest without a version and runs its scripts.
				// Yarn Classic refuses it before fetching, with nothing to evaluate.
				{name: "no-version", manifest: "yarn/git-package-no-version/package.json", outcome: evaluation.OutcomeBlock, failed: true},
				{name: "warn", manifest: "yarn/git-package/package.json", outcome: evaluation.OutcomeWarn},
			} {
				t.Run(generation+"/"+transport+"/"+test.name, func(t *testing.T) {
					executable := yarnTestExecutable(t, variable)
					dependency, remote, sha, marker, ca := yarnGitRemote(t, transport, test.manifest)
					dir, rcName, rc := newYarnGitProject(t, generation)
					if ca != "" {
						t.Setenv("GIT_SSL_CAINFO", ca)
					}
					manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
					if err != nil {
						t.Fatal(err)
					}
					run := runYarnGitThroughProxy(t, executable, []string{"add", "lab-git-pkg@" + dependency}, test.outcome)
					if test.failed {
						assertYarnFailed(t, run)
					} else {
						assertYarnSucceeded(t, run)
					}
					want := []string{remote + "#" + sha}
					if generation == "classic" && test.name == "no-version" {
						want = nil
					}
					if int(run.calls) != len(want) || !slices.Equal(run.sources, want) {
						t.Fatalf("evaluations = %d, sources %v; want %v", run.calls, run.sources, want)
					}
					_, installErr := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg", "package.json"))
					_, markerErr := os.Stat(marker)
					if test.failed {
						if installErr == nil || markerErr == nil {
							t.Fatalf("blocked git dependency installed (%v) or its scripts ran (%v)", installErr == nil, markerErr == nil)
						}
						if after, err := os.ReadFile(filepath.Join(dir, "package.json")); err != nil || !bytes.Equal(after, manifest) {
							t.Fatalf("package.json changed after a block: %s", after)
						}
						if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
							t.Fatal("yarn.lock written after a block")
						}
					} else if installErr != nil || markerErr != nil {
						t.Fatalf("git dependency not installed (%v) or its scripts did not run (%v)", installErr, markerErr)
					}
					if after, err := os.ReadFile(filepath.Join(dir, rcName)); err != nil || string(after) != rc {
						t.Fatalf("%s changed: %q (error %v)", rcName, after, err)
					}
					if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".gitconfig")); err == nil {
						t.Fatal("a Git configuration file was written")
					}
					assertProxyCleaned(t, run.config)
				})
			}
		}
	}
}

// Repositories whose shape changes Yarn 4's checkouts must still be
// evaluated and blocked. A default branch named after its commit keeps the
// checkout of that commit on the branch; a remote HEAD naming a missing branch
// leaves the clone without a checkout, so the commit's checkout starts from an
// unborn HEAD. On the clone path SCFW forces, Yarn Classic fails by itself on
// both: it cannot read the ambiguous commit's manifest, and its git pull fails
// in a clone without a checkout.
func TestYarnGitDependencyRepositoryShapes(t *testing.T) {
	for _, test := range []struct {
		name string
		// reshape changes the bare repository and returns the dependency's selector.
		reshape func(t *testing.T, bare, sha string) string
	}{
		{name: "branch-named-after-commit", reshape: func(t *testing.T, bare, sha string) string {
			yarnGitFixture(t, "-C", bare, "branch", "-m", sha)
			return ""
		}},
		{name: "unborn-remote-head", reshape: func(t *testing.T, bare, _ string) string {
			branch := strings.TrimPrefix(yarnGitFixture(t, "-C", bare, "symbolic-ref", "HEAD"), "refs/heads/")
			yarnGitFixture(t, "-C", bare, "symbolic-ref", "HEAD", "refs/heads/missing")
			return "#" + branch
		}},
	} {
		for _, generation := range []string{"classic", "berry"} {
			t.Run(test.name+"/"+generation, func(t *testing.T) {
				executable := yarnTestExecutable(t, map[string]string{"classic": "SCFW_TEST_YARN_CLASSIC", "berry": "SCFW_TEST_YARN_BERRY"}[generation])
				dependency, remote, sha, marker, _ := yarnGitRemote(t, "ssh", "yarn/git-package/package.json")
				dependency += test.reshape(t, strings.TrimPrefix(remote, "ssh://localhost"), sha)
				dir, _, _ := newYarnGitProject(t, generation)
				run := runYarnGitThroughProxy(t, executable, []string{"add", "lab-git-pkg@" + dependency}, evaluation.OutcomeBlock)
				assertYarnFailed(t, run)
				want := []string{remote + "#" + sha}
				if generation == "classic" {
					want = nil
				}
				if !slices.Equal(run.sources, want) {
					t.Fatalf("sources = %v, want %v", run.sources, want)
				}
				if _, err := os.Stat(marker); err == nil {
					t.Fatal("blocked git dependency's scripts ran")
				}
				if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg")); err == nil {
					t.Fatal("blocked git dependency was installed")
				}
			})
		}
	}
}

// Yarn 4 prepares a git dependency configured for npm with npm install, which
// checks out that repository's own git dependencies; those are evaluated too.
func TestYarnGitDependencyPreparedWithNpm(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm required for Yarn 4 npm preparation")
	}
	inner, innerRemote, innerSHA, marker, _ := yarnGitRemote(t, "ssh", "npm/git-package/package.json")
	bare := yarnGitRepository(t, map[string]string{
		"package.json":      fmt.Sprintf(readProxyFixture(t, "yarn/git-package-npm/package.json.tmpl"), inner),
		"package-lock.json": readProxyFixture(t, "yarn/git-package-npm/package-lock.json"),
	})
	dir, _, _ := newYarnGitProject(t, "berry")
	t.Setenv("npm_config_audit", "false")
	t.Setenv("npm_config_fund", "false")
	run := runYarnGitThroughProxyWith(t, executable, []string{"add", "lab-git-outer@git+ssh://git@localhost" + bare}, func(pkg pm.Package) evaluation.Outcome {
		if pkg.Name == "lab-git-pkg" {
			return evaluation.OutcomeBlock
		}
		return evaluation.OutcomeAllow
	})
	assertYarnFailed(t, run)
	if want := innerRemote + "#" + innerSHA; !slices.Contains(run.sources, want) {
		t.Fatalf("sources = %v, want the nested dependency %s", run.sources, want)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("blocked nested git dependency's prepare script ran")
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-outer")); err == nil {
		t.Fatal("git dependency with a blocked nested dependency was installed")
	}
}

// Yarn 4 installs a cwd= subdirectory of a repository without a root
// package.json; SCFW identifies git dependencies by the root manifest, so it
// refuses the checkout before Yarn prepares it, whatever the policy.
func TestYarnGitDependencyWithoutRootManifestIsRefused(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	marker := filepath.Join(t.TempDir(), "prepare-marker")
	t.Setenv("SCFW_TEST_PREPARE_MARKER", marker)
	bare := yarnGitRepository(t, map[string]string{"sub/package.json": readProxyFixture(t, "yarn/git-package/package.json")})
	dir, _, _ := newYarnGitProject(t, "berry")
	run := runYarnGitThroughProxy(t, executable, []string{"add", "lab-git-pkg@git+ssh://git@localhost" + bare + "#cwd=sub"}, evaluation.OutcomeAllow)
	assertYarnFailed(t, run)
	if run.calls != 0 {
		t.Fatalf("evaluations = %d, want the checkout refused before evaluation", run.calls)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("unidentified git dependency's scripts ran")
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg")); err == nil {
		t.Fatal("unidentified git dependency was installed")
	}
}

// yarnGitRepository commits files to a bare repository that the fake SSH
// command serves, and returns its path.
func yarnGitRepository(t *testing.T, files map[string]string) string {
	t.Helper()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	ssh, err := filepath.Abs(filepath.Join("testdata", "yarn", "fake-ssh.sh"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSH_COMMAND", ssh)
	source := filepath.Join(t.TempDir(), "source")
	for name, content := range files {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	yarnGitFixture(t, "-C", source, "init", "-q")
	yarnGitFixture(t, "-C", source, "add", ".")
	yarnGitFixture(t, "-C", source, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=SCFW Test",
		"-c", "user.email=scfw@example.invalid", "commit", "-q", "-m", "fixture")
	yarnGitFixture(t, "clone", "-q", "--bare", source, source+".git")
	return source + ".git"
}

func yarnGitFixture(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git fixture: %v %s", err, output)
	}
	return strings.TrimSpace(string(output))
}

// The user's Git proxy and CA apply to Yarn's Git traffic, which SCFW still
// evaluates.
func TestYarnGitDependencyHonorsUserGitSettings(t *testing.T) {
	executable := yarnTestExecutable(t, "SCFW_TEST_YARN_BERRY")
	dependency, remote, sha, _, ca := yarnGitRemote(t, "https", "yarn/git-package/package.json")
	dir, _, _ := newYarnGitProject(t, "berry")
	var hits atomic.Int32
	upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &hits})
	gitConfig := filepath.Join(t.TempDir(), "gitconfig")
	content := "[http]\n\tproxy = " + strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1) + "\n\tsslCAInfo = " + ca + "\n"
	if err := os.WriteFile(gitConfig, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", gitConfig)
	run := runYarnGitThroughProxy(t, executable, []string{"add", "lab-git-pkg@" + dependency}, evaluation.OutcomeAllow)
	assertYarnSucceeded(t, run)
	if hits.Load() == 0 {
		t.Fatal("Yarn's Git traffic did not use the user's http.proxy")
	}
	if want := remote + "#" + sha; !slices.Equal(run.sources, []string{want}) {
		t.Fatalf("sources = %v, want [%s]", run.sources, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-git-pkg", "package.json")); err != nil {
		t.Fatalf("git dependency not installed: %v", err)
	}
	if after, err := os.ReadFile(gitConfig); err != nil || string(after) != content {
		t.Fatalf("the user's Git configuration changed: %q (error %v)", after, err)
	}
	assertProxyCleaned(t, run.config)
}
