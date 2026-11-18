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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

type npmGraphLock struct {
	Packages map[string]struct {
		Version      string            `json:"version"`
		Resolved     string            `json:"resolved"`
		Integrity    string            `json:"integrity"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"packages"`
}
type npmGraphSelection struct {
	Cell     cell           `json:"cell"`
	Commands []fileEvidence `json:"commands"`
	Roots    []candidate    `json:"roots"`
	Leaves   []candidate    `json:"leaves"`
	Locks    []fileEvidence `json:"locks"`
}

func init() {
	discoverers["npm-graph"] = discoverNPMGraph
	revalidators["npm-graph"] = revalidateNPMGraph
	for _, mode := range []string{"resolution", "proxy"} {
		for _, item := range []struct{ id, variant string }{
			{"CORE-03", "graph-allow"}, {"CORE-03", "transitive-block"},
			{"CORE-04", "version-invocations"}, {"CORE-13", "cold-artifacts"},
			{"CORE-13", "metadata-warm-artifacts-cold"}, {"CORE-13", "artifact-warm-offline"},
			{"CORE-15", "already-satisfied"}, {"CORE-15", "empty-project"},
		} {
			suites["npm-graph-cache"] = append(suites["npm-graph-cache"], scenario{Scenario: item.id, Variant: "npm-" + mode + "-" + item.variant, Manager: "npm", Mode: mode, Backend: "local", RegistryProfile: "public-npm", DiscoveryKey: "npm-graph", Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runNPMGraph(r, item.variant) }})
		}
	}
}

// Dependency selection belongs to the native manager. The maintained pool has
// one required leaf, permitting an exact graph oracle without a second resolver.
func discoverNPMGraph(ctx context.Context, c cell, output string) (candidate, error) {
	var pool struct{ Root, Leaf string }
	if err := readJSON("testdata/graph_cache/npm/npm.json", &pool); err != nil {
		return candidate{}, err
	}
	var metadata npmMetadata
	evidence, err := fetchJSON(ctx, npmMetadataURL(pool.Root), filepath.Join(output, "root.json"), &metadata)
	if err != nil {
		return candidate{}, err
	}
	var leafMetadata npmMetadata
	leafEvidence, err := fetchJSON(ctx, npmMetadataURL(pool.Leaf), filepath.Join(output, "leaf.json"), &leafMetadata)
	if err != nil {
		return candidate{}, err
	}
	now := time.Now().UTC()
	var choices []candidate
	for version, release := range metadata.Versions {
		if len(release.Dependencies) != 1 || release.Dependencies[pool.Leaf] == "" || len(release.OptionalDependencies)+len(release.PeerDependencies) != 0 || !compatibleNodeFloor(release.Engines.Node, c.RuntimeVersion) {
			continue
		}
		download, err := npmGraphArtifact(metadata, version)
		if err != nil || download.UploadedAt.After(now.Add(-48*time.Hour)) {
			continue
		}
		choices = append(choices, candidate{Ecosystem: "npm", Project: metadata.Name, Version: version, Module: metadata.Name, Property: "required-transitive", Metadata: []metadataEvidence{evidence}, Artifacts: []artifact{download}, ObservedAt: now, LatestValidStart: now.Add(24 * time.Hour)})
	}
	slices.SortFunc(choices, func(a, b candidate) int { return b.Artifacts[0].UploadedAt.Compare(a.Artifacts[0].UploadedAt) })
	if len(choices) < 2 {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("need two eligible %s releases with required %s", pool.Root, pool.Leaf))
	}
	selection := npmGraphSelection{Cell: c, Roots: choices[:2]}
	for i, root := range selection.Roots {
		runRoot := filepath.Join(output, fmt.Sprintf("native-%d", i))
		env, err := isolatedEnvironment(runRoot)
		if err != nil {
			return candidate{}, err
		}
		r := &caseRun{Context: ctx, Cell: c, Root: runRoot, WorkDir: filepath.Join(runRoot, "work"), Env: env, Result: &result{Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}}
		if _, err := prepareNPMProject(r); err != nil {
			return candidate{}, err
		}
		if _, err := r.Command("resolve", c.Executable, "install", "--package-lock-only", "--ignore-scripts", root.Project+"@"+root.Version); err != nil {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
		}
		if err := writeJSON(filepath.Join(runRoot, "commands.json"), r.Result.Commands); err != nil {
			return candidate{}, err
		}
		commands, err := digestFile(filepath.Join(runRoot, "commands.json"))
		if err != nil {
			return candidate{}, err
		}
		selection.Commands = append(selection.Commands, commands)
		lockPath := filepath.Join(r.WorkDir, "package-lock.json")
		var lock npmGraphLock
		if err := readJSON(lockPath, &lock); err != nil {
			return candidate{}, err
		}
		leafEntry := lock.Packages["node_modules/"+pool.Leaf]
		download, err := npmArtifact(leafMetadata, leafEntry.Version)
		if err != nil || !compatibleNodeFloor(leafMetadata.Versions[leafEntry.Version].Engines.Node, c.RuntimeVersion) || download.UploadedAt.After(now.Add(-48*time.Hour)) {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("native leaf is ineligible: %v", err))
		}
		leaf := candidate{Ecosystem: "npm", Project: pool.Leaf, Version: leafEntry.Version, Module: pool.Leaf, Property: "required-leaf", Metadata: []metadataEvidence{leafEvidence}, Artifacts: []artifact{download}, ObservedAt: now, LatestValidStart: now.Add(24 * time.Hour)}
		if err := matchNPMGraph(lock, root, leaf); err != nil {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
		}
		digest, err := digestFile(lockPath)
		if err != nil {
			return candidate{}, err
		}
		selection.Locks = append(selection.Locks, digest)
		selection.Leaves = append(selection.Leaves, leaf)
	}
	selected := selection.Roots[0]
	path := filepath.Join(output, "selection.json")
	if err := writeJSON(path, selection); err != nil {
		return candidate{}, err
	}
	digest, err := digestFile(path)
	selected.Selection = &digest
	selected.Constraints = []string{"native npm " + c.ManagerVersion, "Node " + c.RuntimeVersion, "exact two-node required graph; no optional/peer dependencies"}
	selected.Evidence = []string{"two newest eligible root versions; native package-lock-only graphs retained; no reroll after execution"}
	return selected, err
}
func npmGraphArtifact(metadata npmMetadata, version string) (artifact, error) {
	release := metadata.Versions[version]
	release.Dependencies = nil
	copy := metadata
	copy.Versions = map[string]npmRelease{version: release}
	return npmArtifact(copy, version)
}
func loadNPMGraph(c candidate) (npmGraphSelection, error) {
	var selection npmGraphSelection
	if c.Selection == nil {
		return selection, fmt.Errorf("missing native graph selection")
	}
	if err := verifyGraphFile(*c.Selection); err != nil {
		return selection, err
	}
	if err := readJSON(c.Selection.Path, &selection); err != nil {
		return selection, err
	}
	if len(selection.Roots) != 2 || len(selection.Leaves) != 2 || len(selection.Locks) != 2 || selection.Roots[0].Project != c.Project || selection.Roots[0].Version != c.Version || selection.Roots[0].Version == selection.Roots[1].Version {
		return selection, fmt.Errorf("invalid graph/two-version selection")
	}
	for _, node := range append(slices.Clone(selection.Roots), selection.Leaves...) {
		if err := validateCandidate(node, time.Now().UTC()); err != nil {
			return selection, err
		}
	}
	for _, lock := range append(slices.Clone(selection.Locks), selection.Commands...) {
		if err := verifyGraphFile(lock); err != nil {
			return selection, err
		}
	}
	return selection, nil
}
func verifyGraphFile(expected fileEvidence) error {
	actual, err := digestFile(expected.Path)
	if err != nil {
		return err
	}
	if actual.SHA256 != expected.SHA256 {
		return fmt.Errorf("selected graph changed: %s", expected.Path)
	}
	return nil
}
func matchNPMGraph(lock npmGraphLock, root, leaf candidate) error {
	if len(lock.Packages) != 3 {
		return fmt.Errorf("expected exactly root and required leaf in native graph")
	}
	for _, node := range []candidate{root, leaf} {
		entry := lock.Packages["node_modules/"+node.Project]
		if entry.Version != node.Version || entry.Resolved != node.Artifacts[0].URL || entry.Integrity != node.Artifacts[0].Integrity {
			return fmt.Errorf("native graph artifact mismatch for %s", node.Project)
		}
	}
	if len(lock.Packages[""].Dependencies) != 1 || lock.Packages[""].Dependencies[root.Project] == "" || len(lock.Packages["node_modules/"+root.Project].Dependencies) != 1 || lock.Packages["node_modules/"+root.Project].Dependencies[leaf.Project] == "" {
		return fmt.Errorf("missing required root -> leaf edge")
	}
	return nil
}
func revalidateNPMGraph(ctx context.Context, c candidate, output string) error {
	selection, err := loadNPMGraph(c)
	if err != nil {
		return err
	}
	for i, root := range selection.Roots {
		var metadata npmMetadata
		if _, err := fetchJSON(ctx, npmMetadataURL(root.Project), filepath.Join(output, fmt.Sprintf("root-%d.json", i)), &metadata); err != nil {
			return err
		}
		current, err := npmGraphArtifact(metadata, root.Version)
		expected := root.Artifacts[0]
		var lock npmGraphLock
		if err := readJSON(selection.Locks[i].Path, &lock); err != nil {
			return err
		}
		dep := metadata.Versions[root.Version].Dependencies
		if err != nil || current != expected || len(dep) != 1 || dep[selection.Leaves[i].Project] != lock.Packages["node_modules/"+root.Project].Dependencies[selection.Leaves[i].Project] {
			return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("required graph metadata changed: %v", err))
		}
		if err := revalidateNPM(ctx, selection.Leaves[i], filepath.Join(output, fmt.Sprint(i))); err != nil {
			return err
		}
	}
	return nil
}

func runNPMGraph(r *caseRun, variant string) error {
	selection, err := loadNPMGraph(r.Candidate)
	if err != nil {
		return err
	}
	if selection.Cell.ID != r.Cell.ID || selection.Cell.ManagerVersion != r.Cell.ManagerVersion || selection.Cell.RuntimeVersion != r.Cell.RuntimeVersion || selection.Cell.Executable != r.Cell.Executable {
		return fmt.Errorf("graph was resolved for another cell")
	}
	r.Result.Observations["selected_graph"] = r.Candidate.Selection
	indices := []int{0}
	if variant == "version-invocations" {
		indices = []int{0, 1, 0}
	}
	for phase, index := range indices {
		run := *r
		run.Root = filepath.Join(r.Root, fmt.Sprintf("phase-%d", phase))
		run.WorkDir = filepath.Join(run.Root, "work")
		run.Env, err = isolatedEnvironment(run.Root)
		if err != nil {
			return err
		}
		// Reuse the policy/verifier home across independent version invocations,
		// while each invocation gets fresh manager state and artifact cache.
		run.Env["SCFW_HOME"] = r.Env["SCFW_HOME"]
		run.Candidate = selection.Roots[index]
		if _, err := prepareNPMProject(&run); err != nil {
			return err
		}
		if r.Spec.Mode == "proxy" {
			run.Env["SCFW_PROXY_ENABLED"] = "1"
		}
		if variant == "empty-project" {
			return npmGraphCommand(&run, selection.Leaves[index], "empty", false, true, false, nil)
		}
		if err := npmCacheEvidence(&run, "cold", []candidate{run.Candidate, selection.Leaves[index]}, false); err != nil {
			return err
		}
		if err := copyGraphLock(&run, selection.Locks[index].Path); err != nil {
			return err
		}
		leaf := selection.Leaves[index]
		if variant == "version-invocations" {
			target := selection.Roots[0]
			if err := writeFinding(&run, "npm", target.Project, target.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		if variant == "transitive-block" || variant == "metadata-warm-artifacts-cold" {
			if err := writeFinding(&run, "npm", leaf.Project, leaf.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		if variant == "metadata-warm-artifacts-cold" {
			for _, node := range []candidate{run.Candidate, leaf} {
				if _, err := run.Command("prime-metadata", run.Cell.Executable, "view", node.Project+"@"+node.Version, "--json"); err != nil {
					return err
				}
			}
			if err := npmCacheEvidence(&run, "metadata-only", []candidate{run.Candidate, leaf}, false); err != nil {
				return err
			}
		}
		if variant == "artifact-warm-offline" || variant == "already-satisfied" {
			if err := npmGraphCommand(&run, leaf, "prime", false, false, false, nil); err != nil {
				return err
			}
			if err := npmCacheEvidence(&run, "artifacts-warm", []candidate{run.Candidate, leaf}, true); err != nil {
				return err
			}
			if err := writeFinding(&run, "npm", run.Candidate.Project, run.Candidate.Version, "CRITICAL"); err != nil {
				return err
			}
			if variant == "artifact-warm-offline" {
				if err := os.RemoveAll(filepath.Join(run.WorkDir, "node_modules")); err != nil {
					return err
				}
				if err := npmGraphCommand(&run, leaf, "offline", r.Spec.Mode == "resolution", r.Spec.Mode == "proxy", true, []string{"--offline"}); err != nil {
					return err
				}
				r.Result.Observations["coverage_boundary"] = "npm --offline reuses cached artifacts; proxy promises no new package evaluation without artifact traffic; SCFW verifier traffic is separate"
			} else if err := npmGraphCommand(&run, leaf, "satisfied", false, true, false, nil); err != nil {
				return err
			}
			continue
		}
		blocked := variant == "transitive-block" || variant == "metadata-warm-artifacts-cold" || variant == "version-invocations" && index == 0
		if err := npmGraphCommand(&run, leaf, "install", blocked, false, false, nil); err != nil {
			return err
		}
	}
	return nil
}
func copyGraphLock(r *caseRun, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.WorkDir, "package-lock.json"), body, 0600); err != nil {
		return err
	}
	return writeJSON(filepath.Join(r.WorkDir, "package.json"), map[string]any{"name": "scfw-e2e-graph", "version": "1.0.0", "private": true, "dependencies": map[string]string{r.Candidate.Project: r.Candidate.Version}})
}
func npmCacheEvidence(r *caseRun, label string, nodes []candidate, artifacts bool) error {
	script, err := filepath.Abs("testdata/graph_cache/npm/inspect_cache.cjs")
	if err != nil {
		return err
	}
	command, err := r.Command("cache-"+label, r.Cell.Runtime, script, r.Cell.Executable, r.Env["npm_config_cache"])
	if err != nil {
		return err
	}
	body, err := os.ReadFile(command.Stdout.Path)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if strings.Contains(string(body), node.Artifacts[0].URL) != artifacts {
			return fmt.Errorf("cache %s has unexpected artifact entry for %s", label, node.Project)
		}
		if label == "metadata-only" && !strings.Contains(string(body), npmMetadataURL(node.Project)) {
			return fmt.Errorf("metadata cache did not retain %s", node.Project)
		}
	}
	return nil
}
func npmGraphCommand(r *caseRun, leaf candidate, label string, blocked, noTargets, offline bool, extra []string) error {
	r.Env["SCFW_LOG_FILE"] = filepath.Join(r.Root, label+"-policy.jsonl")
	before, err := os.ReadFile(filepath.Join(r.WorkDir, "package-lock.json"))
	if err != nil {
		return err
	}
	args := []string{r.Binary, "run", "--error-on-block", "--", "npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=http"}
	if label != "empty" {
		args = append(args, r.Candidate.Project+"@"+r.Candidate.Version)
	}
	args = append(args, extra...)
	command, commandErr := r.Command(label, args...)
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %w", commandErr))
	}
	if (command.ExitCode != 0) != blocked {
		return fmt.Errorf("%s exit%d, blocked=%t: %v", label, command.ExitCode, blocked, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("wrong inspection mode")
	}
	blockedNode := r.Candidate
	if strings.HasSuffix(r.Spec.Variant, "transitive-block") || strings.HasSuffix(r.Spec.Variant, "metadata-warm-artifacts-cold") {
		blockedNode = leaf
	}
	expected := []candidate{r.Candidate, leaf}
	if blocked {
		expected = []candidate{blockedNode}
	}
	if err := assertGraphPolicy(r, expected, blocked, noTargets); err != nil {
		return err
	}
	if blocked && r.Spec.Mode == "resolution" {
		after, err := os.ReadFile(filepath.Join(r.WorkDir, "package-lock.json"))
		if err != nil {
			return err
		}
		if !bytes.Equal(before, after) {
			return fmt.Errorf("resolution BLOCK changed lock")
		}
	}
	if label != "empty" {
		for _, node := range []candidate{r.Candidate, leaf} {
			copy := *r
			copy.Candidate = node
			if blocked {
				// Proxy can have installed other allowed packages; only the exact blocked
				// target must be absent. Resolution preserves the entire pre-install state.
				if node.Project != blockedNode.Project {
					continue
				}
			}
			if err := assertNPMInstall(&copy, blocked); err != nil {
				return err
			}
			r.Result.Observations[label+"-"+filepath.Base(r.Root)+"-"+node.Project] = r.Result.Observations["installed"]
			if !blocked {
				key := label + "-" + filepath.Base(r.Root) + "-" + node.Project
				if err := snapshotGraphEvidence(r, key, filepath.Join(r.WorkDir, "node_modules", node.Project, "package.json")); err != nil {
					return err
				}
				r.Result.Evidence["installed-package"] = r.Result.Evidence[key]
			}
		}
		if !blocked {
			var lock npmGraphLock
			if err := readJSON(filepath.Join(r.WorkDir, "package-lock.json"), &lock); err != nil {
				return err
			}
			if err := matchNPMGraph(lock, r.Candidate, leaf); err != nil {
				return err
			}
		}
	}
	httpLines := regexp.MustCompile(`(?m)^npm http .+$`).FindAllString(string(stderr), -1)
	r.Result.Observations[label+"-"+filepath.Base(r.Root)+"-npm-http"] = httpLines
	if !blocked && !noTargets && !offline {
		for _, node := range []candidate{r.Candidate, leaf} {
			found := false
			for _, line := range httpLines {
				if strings.Contains(line, node.Artifacts[0].URL) && strings.Contains(line, "GET 200") {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("cold artifact download not observed for %s", node.Project)
			}
		}
	}
	if offline && strings.Contains(string(stderr), "(cache miss)") {
		return fmt.Errorf("offline command missed its artifact cache")
	}
	if err := snapshotGraphEvidence(r, label+"-lock-"+filepath.Base(r.Root), filepath.Join(r.WorkDir, "package-lock.json")); err != nil {
		return err
	}
	if err := assertCleanup(r, string(stderr)); err != nil {
		return err
	}
	return snapshotGraphEvidence(r, label+"-cleanup-"+filepath.Base(r.Root), filepath.Join(r.Root, "cleanup.json"))
}
func assertGraphPolicy(r *caseRun, nodes []candidate, blocked, noTargets bool) error {
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if noTargets && r.Spec.Mode == "proxy" && os.IsNotExist(err) {
		r.Result.Observations["no_evaluation_"+filepath.Base(r.Env["SCFW_LOG_FILE"])] = true
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "ALLOW"
		return nil
	}
	if err != nil {
		return err
	}
	if err := r.Keep("policy-"+filepath.Base(r.Root)+"-"+filepath.Base(r.Env["SCFW_LOG_FILE"]), r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	count := 0
	for _, record := range records {
		count += len(record.Packages)
	}
	if noTargets {
		if count != 0 || r.Spec.Mode == "proxy" || len(records) != 1 || records[0].Outcome != "ALLOW" {
			return fmt.Errorf("unexpected policy evaluation for no targets: %+v", records)
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "ALLOW", "ALLOW"
		return nil
	}
	if blocked {
		for _, node := range nodes {
			for _, record := range records {
				for _, pkg := range record.Packages {
					if pkg.Name == node.Project && pkg.Version == node.Version && pkg.Outcome == "BLOCK" {
						if err := assertPolicy([]policyRecord{record}, node, r.Cell.Manager, r.Cell.Executable, "BLOCK"); err != nil {
							return err
						}
						r.Result.PolicyOutcome, r.Result.ResolvedAction = "BLOCK", "BLOCK"
						return nil
					}
				}
			}
		}
		return fmt.Errorf("missing exact graph BLOCK")
	}
	for _, node := range nodes {
		if err := assertPolicy(records, node, r.Cell.Manager, r.Cell.Executable, "ALLOW"); err != nil {
			return err
		}
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = "ALLOW", "ALLOW"
	return nil
}
func TestHarnessNPMGraph(t *testing.T) {
	root := candidate{Project: "root", Version: "1", Artifacts: []artifact{{URL: "root-url", Integrity: "root-hash"}}}
	leaf := candidate{Project: "leaf", Version: "2", Artifacts: []artifact{{URL: "leaf-url", Integrity: "leaf-hash"}}}
	var fixtures map[string]npmGraphLock
	if err := readJSON("testdata/graph_cache/npm/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	for name, lock := range fixtures {
		err := matchNPMGraph(lock, root, leaf)
		if (err == nil) != (name == "required") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestHarnessNPMGraphSelection(t *testing.T) {
	now := time.Now().UTC()
	node := candidate{Ecosystem: "npm", Project: "root", Version: "1", Metadata: []metadataEvidence{{URL: "registry"}}, Artifacts: []artifact{{Name: "root.tgz", URL: "artifact", Integrity: "digest", UploadedAt: now.Add(-time.Hour)}}, ObservedAt: now, LatestValidStart: now.Add(time.Hour)}
	directory := t.TempDir()
	lock := filepath.Join(directory, "lock.json")
	if err := os.WriteFile(lock, []byte("native graph"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := digestFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	second := node
	second.Version = "2"
	selection := npmGraphSelection{Roots: []candidate{node, second}, Leaves: []candidate{node, node}, Locks: []fileEvidence{digest, digest}}
	save := func(value npmGraphSelection) candidate {
		t.Helper()
		path := filepath.Join(directory, "selection.json")
		if err := writeJSON(path, value); err != nil {
			t.Fatal(err)
		}
		digest, err := digestFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c := node
		c.Selection = &digest
		return c
	}
	if _, err := loadNPMGraph(node); err == nil {
		t.Fatal("accepted missing selection")
	}
	valid := save(selection)
	if _, err := loadNPMGraph(valid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid.Selection.Path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNPMGraph(valid); err == nil {
		t.Fatal("accepted tampered selection")
	}
	expired := selection
	expired.Leaves = slices.Clone(selection.Leaves)
	expired.Leaves[0].LatestValidStart = now.Add(-time.Second)
	if _, err := loadNPMGraph(save(expired)); err == nil {
		t.Fatal("accepted stale selected leaf")
	}
	valid = save(selection)
	if err := os.WriteFile(lock, []byte("changed graph"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNPMGraph(valid); err == nil {
		t.Fatal("accepted tampered native graph")
	}
}

// Preserve evidence before a named cache phase removes or mutates manager state.
func snapshotGraphEvidence(r *caseRun, label, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	snapshot := filepath.Join(r.Root, "snapshots", label+".json")
	if err := os.MkdirAll(filepath.Dir(snapshot), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(snapshot, body, 0600); err != nil {
		return err
	}
	return r.Keep(label, snapshot)
}
