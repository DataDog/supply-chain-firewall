//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"
)

func prepareProjectGraph(r *caseRun) (string, error) {
	var python string
	if r.Cell.Manager == "poetry" {
		var err error
		python, err = preparePoetry(r, "direct")
		if err != nil {
			return "", err
		}
	} else {
		if _, _, err := prepareUV(r, uvOptions{flag: "1"}); err != nil {
			return "", err
		}
		python = filepath.Join(r.WorkDir, ".venv", "bin", "python")
		if _, err := r.Command("project-venv", r.Cell.Runtime, "-m", "venv", "--without-pip", filepath.Dir(filepath.Dir(python))); err != nil {
			return "", err
		}
	}
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	} else {
		delete(r.Env, "SCFW_PROXY_ENABLED")
	}
	return python, writeProjectGraphManifest(r)
}
func writeProjectGraphManifest(r *caseRun) error {
	name := "pyproject.toml.tmpl"
	if r.Cell.Manager == "uv" {
		name = "configurations.toml.tmpl"
	}
	tmpl, err := template.ParseFiles(filepath.Join(projectGraphFixtures, name))
	if err != nil {
		return err
	}
	var body bytes.Buffer
	values := map[string]string{"Project": r.Candidate.Project, "Version": r.Candidate.Version, "Python": strings.Join(strings.Split(r.Cell.RuntimeVersion, ".")[:2], ".")}
	if err := tmpl.Execute(&body, values); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.WorkDir, "pyproject.toml"), body.Bytes(), 0600)
}
func projectGraphLockArgs(r *caseRun) []string {
	if r.Cell.Manager == "poetry" {
		return []string{r.Cell.Executable, "--no-interaction", "lock"}
	}
	return []string{r.Cell.Executable, "lock", "--python", r.Cell.Runtime}
}
func projectGraphCache(r *caseRun, label string, leaf candidate, metadata, artifacts bool) error {
	script, err := filepath.Abs(filepath.Join(projectGraphFixtures, "inspect_cache.py"))
	if err != nil {
		return err
	}
	cache := r.Env["POETRY_CACHE_DIR"]
	if r.Cell.Manager == "uv" {
		cache = r.Env["UV_CACHE_DIR"]
	}
	command, err := r.Command("cache-"+label, r.Cell.Runtime, "-I", script, r.Cell.Manager, cache, r.Candidate.Project, leaf.Project)
	if err != nil {
		return err
	}
	var state struct {
		Metadata  bool
		Artifacts map[string]bool
	}
	if err := readJSON(command.Stdout.Path, &state); err != nil {
		return err
	}
	if metadata && !state.Metadata {
		return fmt.Errorf("%s did not retain registry metadata", label)
	}
	for _, node := range []candidate{r.Candidate, leaf} {
		if state.Artifacts[node.Project] != artifacts {
			return fmt.Errorf("%s artifact cache mismatch for %s", label, node.Project)
		}
		if artifacts && r.Cell.Manager == "poetry" {
			ev, err := poetryDownloadedArchive(cache, node)
			if err != nil {
				return err
			}
			r.Result.Evidence[label+"-"+node.Project+"-"+filepath.Base(r.Root)] = ev
		}
	}
	return nil
}
func projectGraphOffline(r *caseRun, offline bool) (func() error, error) {
	if !offline {
		return func() error { return nil }, nil
	}
	artifactURL, err := url.Parse(r.Candidate.Artifacts[0].URL)
	if err != nil {
		return nil, err
	}
	// Registry metadata and ordinary verifier services remain live. The guard
	// refuses artifact traffic only; it never substitutes registry content.
	var mu sync.Mutex
	var observed, denied []string
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, err := net.SplitHostPort(req.Host)
		blocked := err != nil || host == artifactURL.Hostname()
		mu.Lock()
		observed = append(observed, req.Method+" "+req.Host)
		if blocked {
			denied = append(denied, req.Method+" "+req.Host)
		}
		mu.Unlock()
		if blocked || req.Method != http.MethodConnect {
			http.Error(w, "artifact network disabled", http.StatusServiceUnavailable)
			return
		}
		upstream, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		deadline, _ := r.Context.Deadline()
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			return
		}
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close() }()
		_, _ = io.Copy(client, upstream)
	}))
	r.Env["HTTP_PROXY"], r.Env["HTTPS_PROXY"] = guard.URL, guard.URL
	r.Env["NO_PROXY"] = ""
	return func() error {
		guard.Close()
		mu.Lock()
		defer mu.Unlock()
		r.Result.Observations["offline_artifact_guard"] = map[string]any{"refused_host": artifactURL.Hostname(), "observed_connects": observed, "artifact_attempts": denied}
		if len(denied) != 0 {
			return fmt.Errorf("offline artifact reuse attempted downloads: %v", denied)
		}
		return nil
	}, nil
}
func projectGraphCommand(r *caseRun, leaf candidate, python, label string, blocked, noTargets, offline bool) error {
	r.Env["SCFW_LOG_FILE"] = filepath.Join(r.Root, label+"-policy.jsonl")
	manifest, err := digestFile(filepath.Join(r.WorkDir, "pyproject.toml"))
	if err != nil {
		return err
	}
	lock, err := digestFile(filepath.Join(r.WorkDir, r.Cell.Manager+".lock"))
	if err != nil {
		return err
	}
	args := []string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", r.Cell.Manager}
	if r.Cell.Manager == "poetry" {
		args = append(args, "--no-interaction", "install", "--no-root", "-vv")
	} else {
		args = append(args, "sync", "--frozen", "--no-install-project", "--python", r.Cell.Runtime, "-v")
		if offline {
			args = append(args, "--offline")
		}
	}
	command, commandErr := r.Command(label, args...)
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if (command.ExitCode != 0) != blocked {
		return fmt.Errorf("%s exit=%d blocked=%t: %v", label, command.ExitCode, blocked, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("wrong project graph inspection mode")
	}
	for _, ev := range []fileEvidence{manifest, lock} {
		if err := verifyGraphFile(ev); err != nil {
			return fmt.Errorf("protected project changed: %w", err)
		}
		if err := snapshotGraphEvidence(r, label+"-"+filepath.Base(ev.Path)+"-"+filepath.Base(r.Root), ev.Path); err != nil {
			return err
		}
	}
	expected := []candidate{r.Candidate, leaf}
	blockedNode := r.Candidate
	if strings.HasSuffix(r.Spec.Variant, "transitive-block") || strings.HasSuffix(r.Spec.Variant, "metadata-warm-artifacts-cold") {
		blockedNode = leaf
	}
	if blocked {
		expected = []candidate{blockedNode}
	}
	if err := assertGraphPolicy(r, expected, blocked, noTargets); err != nil {
		return err
	}
	if label != "empty" {
		script, err := filepath.Abs(filepath.Join(poetryFixtures, "inspect_install.py"))
		if err != nil {
			return err
		}
		for _, node := range []candidate{r.Candidate, leaf} {
			if blocked && node.Project != blockedNode.Project {
				continue
			}
			state, err := r.Command("state-"+label, python, "-I", script, node.Project, node.Module)
			if err != nil {
				return err
			}
			var actual struct {
				Present, Imported bool
				Version           string
			}
			if err := readJSON(state.Stdout.Path, &actual); err != nil {
				return err
			}
			if actual.Present == blocked || !blocked && (actual.Version != node.Version || !actual.Imported) {
				return fmt.Errorf("unexpected installed %s state: %+v", node.Project, actual)
			}
		}
	}
	if !blocked && !noTargets {
		if err := projectGraphCache(r, label+"-after", leaf, false, true); err != nil {
			return err
		}
	}
	leftovers, err := filepath.Glob(filepath.Join(r.Root, ".scfw-poetry-*"))
	if err != nil {
		return err
	}
	if len(leftovers) != 0 {
		return fmt.Errorf("Poetry temporary projects remain: %v", leftovers)
	}
	if err := assertCleanup(r, string(stderr)); err != nil {
		return err
	}
	return snapshotGraphEvidence(r, label+"-cleanup-"+filepath.Base(r.Root), filepath.Join(r.Root, "cleanup.json"))
}

func TestHarnessProjectGraph(t *testing.T) {
	root := candidate{Project: "root", Version: "1", Artifacts: []artifact{{Name: "root.whl", SHA256: "root-hash"}}}
	leaf := candidate{Project: "leaf", Version: "2", Artifacts: []artifact{{Name: "leaf.whl", SHA256: "leaf-hash"}}}
	var fixtures map[string][]projectGraphNode
	if err := readJSON(filepath.Join(projectGraphFixtures, "responses.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for name, nodes := range fixtures {
		if err := matchProjectGraph(nodes, root, leaf); (err == nil) != (name == "required") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestHarnessProjectGraphOfflineGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r := &caseRun{Context: ctx, Env: map[string]string{}, Candidate: candidate{Artifacts: []artifact{{URL: "https://artifact.invalid/package.whl"}}}, Result: &result{Observations: map[string]any{}}}
	stop, err := projectGraphOffline(r, true)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := url.Parse(r.Env["HTTPS_PROXY"])
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, requestErr := client.Get(r.Candidate.Artifacts[0].URL)
	if response != nil {
		response.Body.Close()
	}
	guardErr := stop()
	if requestErr == nil || guardErr == nil || !strings.Contains(guardErr.Error(), "CONNECT artifact.invalid:443") {
		t.Fatalf("artifact guard did not reject and retain the download: request=%v guard=%v", requestErr, guardErr)
	}
}
