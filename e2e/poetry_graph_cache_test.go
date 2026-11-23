//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const projectGraphFixtures = "testdata/poetry_uv_graph_cache"

type projectGraphSelection struct {
	pipGraphSelection
	Manifests []fileEvidence `json:"manifests"`
}
type projectGraphNode struct {
	Name, Version string
	Files         map[string]string
	Required      bool
}

func init() {
	discoverers["poetry-uv-graph"] = discoverProjectGraph
	revalidators["poetry-uv-graph"] = revalidatePipGraph
	for _, manager := range []string{"poetry", "uv"} {
		modes := []string{"proxy"}
		if manager == "poetry" {
			modes = []string{"resolution", "proxy"}
		}
		for _, mode := range modes {
			for _, item := range []struct{ id, variant string }{
				{"CORE-03", "graph-allow"}, {"CORE-03", "transitive-block"}, {"CORE-04", "version-invocations"},
				{"CORE-13", "cold-artifacts"}, {"CORE-13", "metadata-warm-artifacts-cold"}, {"CORE-13", "artifact-warm-http"}, {"CORE-13", "offline-artifact-reuse"},
				{"CORE-15", "already-satisfied"}, {"CORE-15", "empty-project"},
			} {
				suites["poetry-uv-graphs-cache"] = append(suites["poetry-uv-graphs-cache"], scenario{Scenario: item.id, Variant: manager + "-" + mode + "-" + item.variant, Manager: manager, Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "poetry-uv-graph", Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runProjectGraph(r, item.variant) }})
			}
		}
	}
}

func discoverProjectGraph(ctx context.Context, c cell, output string) (candidate, error) {
	var pool struct{ Root, Leaf, RootModule, LeafModule string }
	if err := readJSON("testdata/graph_cache/pip/candidates.json", &pool); err != nil {
		return candidate{}, err
	}
	var metadata pypiMetadata
	evidence, err := fetchJSON(ctx, "https://pypi.org/pypi/"+pool.Root+"/json", filepath.Join(output, "root.json"), &metadata)
	if err != nil {
		return candidate{}, err
	}
	now := time.Now().UTC()
	var choices []candidate
	for version, files := range metadata.Releases {
		if !regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(version) {
			continue
		}
		for _, file := range files {
			if eligiblePipGraphFile(file, c, now) {
				choices = append(choices, pipGraphCandidate(pool.Root, version, pool.RootModule, file, evidence, now))
				break
			}
		}
	}
	slices.SortFunc(choices, func(a, b candidate) int { return b.Artifacts[0].UploadedAt.Compare(a.Artifacts[0].UploadedAt) })
	if len(choices) < 2 {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("need two eligible graph root versions"))
	}
	selection := projectGraphSelection{pipGraphSelection: pipGraphSelection{Cell: c, Roots: choices[:2]}}
	for i, root := range selection.Roots {
		directory := filepath.Join(output, fmt.Sprintf("native-%d", i))
		env, err := isolatedEnvironment(directory)
		if err != nil {
			return candidate{}, err
		}
		r := &caseRun{Context: ctx, Cell: c, Candidate: root, Root: directory, WorkDir: filepath.Join(directory, "work"), Env: env, Result: &result{Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}}
		if _, err := prepareProjectGraph(r); err != nil {
			return candidate{}, err
		}
		command, err := r.Command("native-lock", projectGraphLockArgs(r)...)
		if err != nil {
			return candidate{}, classified("INFRASTRUCTURE_FAILURE", err)
		}
		selection.Commands = append(selection.Commands, command)
		path := filepath.Join(r.WorkDir, c.Manager+".lock")
		nodes, err := inspectProjectGraph(r, path, pool.Root, pool.Leaf)
		if err != nil {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
		}
		var leaf candidate
		for _, node := range nodes {
			if node.Name != pool.Leaf {
				continue
			}
			var release pypiMetadata
			ev, err := fetchJSON(ctx, "https://pypi.org/pypi/"+pool.Leaf+"/"+node.Version+"/json", filepath.Join(directory, "leaf.json"), &release)
			if err != nil {
				return candidate{}, err
			}
			for _, file := range release.URLs {
				if eligiblePipGraphFile(file, c, now) && node.Files[file.Filename] == file.Digests.SHA256 {
					leaf = pipGraphCandidate(pool.Leaf, node.Version, pool.LeafModule, file, ev, now)
					break
				}
			}
		}
		if err := matchProjectGraph(nodes, root, leaf); err != nil {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
		}
		lock, err := digestFile(path)
		if err != nil {
			return candidate{}, err
		}
		manifest, err := digestFile(filepath.Join(r.WorkDir, "pyproject.toml"))
		if err != nil {
			return candidate{}, err
		}
		selection.Leaves = append(selection.Leaves, leaf)
		selection.Reports = append(selection.Reports, lock)
		selection.Manifests = append(selection.Manifests, manifest)
		if err := writeJSON(filepath.Join(directory, "commands.json"), r.Result); err != nil {
			return candidate{}, err
		}
	}
	selected := selection.Roots[0]
	path := filepath.Join(output, "selection.json")
	if err := writeJSON(path, selection); err != nil {
		return candidate{}, err
	}
	digest, err := digestFile(path)
	selected.Selection = &digest
	selected.Constraints = []string{"native " + c.Manager + " " + c.ManagerVersion, "Python " + c.RuntimeVersion, "exact required two-node public graph"}
	selected.Evidence = []string{"two newest eligible universal wheels; native lock records exact versions, required edge and artifact SHA256; no reroll after execution"}
	return selected, err
}

func inspectProjectGraph(r *caseRun, path, root, leaf string) ([]projectGraphNode, error) {
	script, err := filepath.Abs(filepath.Join(projectGraphFixtures, "inspect_lock.py"))
	if err != nil {
		return nil, err
	}
	command, err := r.Command("inspect-lock", r.Cell.Runtime, "-I", script, r.Cell.Manager, path, root, leaf)
	if err != nil {
		return nil, err
	}
	var nodes []projectGraphNode
	err = readJSON(command.Stdout.Path, &nodes)
	return nodes, err
}
func matchProjectGraph(nodes []projectGraphNode, root, leaf candidate) error {
	if len(nodes) != 2 || leaf.Project == "" {
		return fmt.Errorf("native lock did not resolve exactly root and required leaf")
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		expected := root
		if node.Name == leaf.Project {
			expected = leaf
		}
		if node.Name != expected.Project || node.Version != expected.Version || seen[node.Name] || node.Files[expected.Artifacts[0].Name] != expected.Artifacts[0].SHA256 || (node.Name == root.Project && !node.Required) {
			return fmt.Errorf("native graph identity, required edge or artifact mismatch: %s", node.Name)
		}
		seen[node.Name] = true
	}
	return nil
}

func runProjectGraph(r *caseRun, variant string) error {
	selection, err := loadPipGraph(r.Candidate)
	if err != nil {
		return err
	}
	if selection.Cell.ID != r.Cell.ID || selection.Cell.Executable != r.Cell.Executable || selection.Cell.ManagerVersion != r.Cell.ManagerVersion || selection.Cell.RuntimeVersion != r.Cell.RuntimeVersion {
		return fmt.Errorf("graph belongs to another native manager cell")
	}
	var project projectGraphSelection
	if err := readJSON(r.Candidate.Selection.Path, &project); err != nil {
		return err
	}
	if len(project.Manifests) != 2 {
		return fmt.Errorf("missing native graph manifests")
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
		run.Env["SCFW_HOME"] = r.Env["SCFW_HOME"]
		run.Candidate = selection.Roots[index]
		leaf := selection.Leaves[index]
		python, err := prepareProjectGraph(&run)
		if err != nil {
			return err
		}
		for _, ev := range []fileEvidence{project.Manifests[index], selection.Reports[index]} {
			if err := verifyGraphFile(ev); err != nil {
				return err
			}
			body, err := os.ReadFile(ev.Path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(run.WorkDir, filepath.Base(ev.Path)), body, 0600); err != nil {
				return err
			}
		}
		if _, err := run.Command("git-init", run.Cell.Git, "init", "--quiet"); err != nil {
			return err
		}
		if variant == "empty-project" {
			run.Candidate = candidate{}
			if err := writeProjectGraphManifest(&run); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(run.WorkDir, run.Cell.Manager+".lock")); err != nil {
				return err
			}
			if _, err := run.Command("empty-lock", projectGraphLockArgs(&run)...); err != nil {
				return err
			}
			if err := projectGraphCommand(&run, leaf, python, "empty", false, true, false); err != nil {
				return err
			}
			continue
		}
		if err := projectGraphCache(&run, "cold", leaf, false, false); err != nil {
			return err
		}
		if variant == "metadata-warm-artifacts-cold" {
			if err := os.Remove(filepath.Join(run.WorkDir, run.Cell.Manager+".lock")); err != nil {
				return err
			}
			if _, err := run.Command("prime-metadata", projectGraphLockArgs(&run)...); err != nil {
				return err
			}
			if err := projectGraphCache(&run, "metadata-only", leaf, true, false); err != nil {
				return err
			}
		}
		if strings.HasPrefix(variant, "artifact-warm") || variant == "offline-artifact-reuse" || variant == "already-satisfied" {
			if err := projectGraphCommand(&run, leaf, python, "prime", false, false, false); err != nil {
				return err
			}
			if err := projectGraphCache(&run, "artifacts-warm", leaf, false, true); err != nil {
				return err
			}
			if err := writeFinding(&run, "PyPI", run.Candidate.Project, run.Candidate.Version, "CRITICAL"); err != nil {
				return err
			}
			if variant == "already-satisfied" {
				if err := projectGraphCommand(&run, leaf, python, "satisfied", false, true, false); err != nil {
					return err
				}
				continue
			}
			if err := os.RemoveAll(filepath.Dir(filepath.Dir(python))); err != nil {
				return err
			}
			if _, err := run.Command("fresh-venv", run.Cell.Runtime, "-m", "venv", "--without-pip", filepath.Dir(filepath.Dir(python))); err != nil {
				return err
			}
			offline := variant == "offline-artifact-reuse"
			stop, err := projectGraphOffline(&run, offline)
			if err != nil {
				return err
			}
			err = projectGraphCommand(&run, leaf, python, "reuse", run.Spec.Mode == "resolution", run.Spec.Mode == "proxy", offline)
			guardErr := stop()
			if err != nil {
				return err
			}
			if guardErr != nil {
				return guardErr
			}
			run.Result.Observations["coverage_boundary"] = "warm manager artifacts produce no proxy package evaluation; resolution still evaluates installation targets; verifier services retain their ordinary behavior"
			continue
		}
		blocked := variant == "transitive-block" || variant == "metadata-warm-artifacts-cold" || variant == "version-invocations" && index == 0
		if variant == "version-invocations" {
			if err := writeFinding(&run, "PyPI", selection.Roots[0].Project, selection.Roots[0].Version, "CRITICAL"); err != nil {
				return err
			}
		} else if blocked {
			if err := writeFinding(&run, "PyPI", leaf.Project, leaf.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		if err := projectGraphCommand(&run, leaf, python, "install", blocked, false, false); err != nil {
			return err
		}
	}
	return nil
}
