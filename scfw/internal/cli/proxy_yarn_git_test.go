// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"encoding/pem"
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
	manager, err := yarn.NewYarn(context.Background(), "yarn", executable)
	if err != nil {
		t.Fatal(err)
	}
	var run yarnProxyRun
	var calls atomic.Int32
	var details bytes.Buffer
	evaluator := proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		calls.Add(1)
		for target := range targets.Items() {
			run.sources = append(run.sources, target.Source)
		}
		return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome}, nil
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

// The user's Git proxy and CA apply to Yarn's Git traffic, which SCFW still
// evaluates, and GIT_SSL_NO_VERIFY does not reach the Git that Yarn runs.
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
	t.Setenv("GIT_SSL_NO_VERIFY", "1")
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
