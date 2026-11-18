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
	"testing"
	"time"
)

type pipGraphReport struct {
	Install []struct {
		Requested bool `json:"requested"`
		Metadata  struct {
			Name, Version string
			RequiresDist  []string `json:"requires_dist"`
		} `json:"metadata"`
		DownloadInfo struct {
			URL         string `json:"url"`
			ArchiveInfo struct {
				Hash   string            `json:"hash"`
				Hashes map[string]string `json:"hashes"`
			} `json:"archive_info"`
		} `json:"download_info"`
	} `json:"install"`
}
type pipGraphSelection struct {
	Cell     cell              `json:"cell"`
	Roots    []candidate       `json:"roots"`
	Leaves   []candidate       `json:"leaves"`
	Reports  []fileEvidence    `json:"reports"`
	Commands []commandEvidence `json:"commands"`
}

func init() {
	discoverers["pip-graph"] = discoverPipGraph
	revalidators["pip-graph"] = revalidatePipGraph
	for _, mode := range []string{"resolution", "proxy"} {
		for _, item := range []struct{ id, variant string }{
			{"CORE-03", "graph-allow"}, {"CORE-03", "transitive-block"}, {"CORE-04", "version-invocations"},
			{"CORE-13", "cold-artifacts"}, {"CORE-13", "metadata-warm-artifacts-cold"}, {"CORE-13", "artifact-warm-http"}, {"CORE-13", "artifact-warm-offline"},
			{"CORE-15", "already-satisfied"}, {"CORE-15", "empty-requirements"},
		} {
			profile := "public-pypi"
			if item.variant == "artifact-warm-offline" {
				profile = "public-pypi-primed-wheelhouse"
			}
			suites["pip-graph-cache"] = append(suites["pip-graph-cache"], scenario{Scenario: item.id, Variant: "pip-" + mode + "-" + item.variant, Manager: "pip", Mode: mode, Backend: "local", RegistryProfile: profile, DiscoveryKey: "pip-graph", Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runPipGraph(r, item.variant) }})
		}
	}
}
func pipGraphCandidate(name, version, module string, file pypiFile, evidence metadataEvidence, now time.Time) candidate {
	return candidate{Ecosystem: "pypi", Project: name, Version: version, Module: module, Property: "required-graph", Metadata: []metadataEvidence{evidence}, Artifacts: []artifact{{Name: file.Filename, URL: file.URL, SHA256: file.Digests.SHA256, UploadedAt: file.UploadTime, RequiresPython: file.RequiresPython}}, ObservedAt: now, LatestValidStart: now.Add(24 * time.Hour)}
}
func eligiblePipGraphFile(file pypiFile, c cell, now time.Time) bool {
	return !file.Yanked && file.UploadTime.Before(now.Add(-48*time.Hour)) && strings.HasSuffix(file.Filename, "-none-any.whl") && compatiblePythonFloor(file.RequiresPython, c.RuntimeVersion) && len(file.Digests.SHA256) == 64 && strings.HasPrefix(file.URL, "https://files.pythonhosted.org/")
}
func discoverPipGraph(ctx context.Context, c cell, output string) (candidate, error) {
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
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("need two compatible public root releases"))
	}
	selection := pipGraphSelection{Cell: c, Roots: choices[:2]}
	for i, root := range selection.Roots {
		directory := filepath.Join(output, fmt.Sprintf("native-%d", i))
		env, err := isolatedEnvironment(directory)
		if err != nil {
			return candidate{}, err
		}
		path := filepath.Join(directory, "report.json")
		command, err := runCommand(ctx, filepath.Join(directory, "command"), env, filepath.Join(directory, "work"), c.Executable, "install", "--dry-run", "--ignore-installed", "--only-binary=:all:", "--report", path, root.Project+"=="+root.Version)
		selection.Commands = append(selection.Commands, command)
		if err != nil {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
		}
		var report pipGraphReport
		if err := readJSON(path, &report); err != nil {
			return candidate{}, err
		}
		var leaf candidate
		for _, entry := range report.Install {
			if entry.Metadata.Name != pool.Leaf {
				continue
			}
			var metadata pypiMetadata
			evidence, err := fetchJSON(ctx, "https://pypi.org/pypi/"+pool.Leaf+"/"+entry.Metadata.Version+"/json", filepath.Join(directory, "leaf.json"), &metadata)
			if err != nil {
				return candidate{}, err
			}
			for _, file := range metadata.URLs {
				if file.URL == entry.DownloadInfo.URL && eligiblePipGraphFile(file, c, now) {
					leaf = pipGraphCandidate(pool.Leaf, entry.Metadata.Version, pool.LeafModule, file, evidence, now)
				}
			}
		}
		if leaf.Project == "" {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("native pip did not resolve eligible required leaf %s", pool.Leaf))
		}
		if err := matchPipGraph(report, root, leaf, false); err != nil {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
		}
		digest, err := digestFile(path)
		if err != nil {
			return candidate{}, err
		}
		selection.Reports = append(selection.Reports, digest)
		selection.Leaves = append(selection.Leaves, leaf)
	}
	selected := selection.Roots[0]
	path := filepath.Join(output, "selection.json")
	if err := writeJSON(path, selection); err != nil {
		return candidate{}, err
	}
	digest, err := digestFile(path)
	selected.Selection = &digest
	selected.Constraints = []string{"native pip " + c.ManagerVersion, "Python " + c.RuntimeVersion, "exact two-node graph; unconditional required leaf"}
	selected.Evidence = []string{"two newest eligible public universal wheels; native dry-run reports retain dependency edges and SHA256; no reroll after execution"}
	return selected, err
}
func loadPipGraph(c candidate) (pipGraphSelection, error) {
	var selection pipGraphSelection
	if c.Selection == nil {
		return selection, fmt.Errorf("missing pip graph selection")
	}
	if err := verifyGraphFile(*c.Selection); err != nil {
		return selection, err
	}
	if err := readJSON(c.Selection.Path, &selection); err != nil {
		return selection, err
	}
	if len(selection.Roots) != 2 || len(selection.Leaves) != 2 || len(selection.Reports) != 2 || len(selection.Commands) != 2 || selection.Roots[0].Project != c.Project || selection.Roots[0].Version != c.Version || selection.Roots[0].Version == selection.Roots[1].Version {
		return selection, fmt.Errorf("invalid pip graph/version selection")
	}
	for _, node := range append(slices.Clone(selection.Roots), selection.Leaves...) {
		if err := validateCandidate(node, time.Now().UTC()); err != nil {
			return selection, err
		}
	}
	for _, evidence := range selection.Reports {
		if err := verifyGraphFile(evidence); err != nil {
			return selection, err
		}
	}
	return selection, nil
}
func revalidatePipGraph(ctx context.Context, c candidate, output string) error {
	selection, err := loadPipGraph(c)
	if err != nil {
		return err
	}
	for i, node := range append(slices.Clone(selection.Roots), selection.Leaves...) {
		if err := revalidatePyPI(ctx, node, filepath.Join(output, fmt.Sprint(i))); err != nil {
			return err
		}
	}
	return nil
}
func matchPipGraph(report pipGraphReport, root, leaf candidate, local bool) error {
	if len(report.Install) != 2 {
		return fmt.Errorf("expected root and required leaf in pip report")
	}
	seen := map[string]bool{}
	for _, entry := range report.Install {
		node := root
		if entry.Metadata.Name == leaf.Project {
			node = leaf
		}
		if entry.Metadata.Name != node.Project || entry.Metadata.Version != node.Version || seen[node.Project] || entry.Requested != (node.Project == root.Project) {
			return fmt.Errorf("incorrect native pip graph identity/requested edge")
		}
		seen[node.Project] = true
		hash := entry.DownloadInfo.ArchiveInfo.Hashes["sha256"]
		if hash == "" {
			hash = strings.TrimPrefix(entry.DownloadInfo.ArchiveInfo.Hash, "sha256=")
		}
		if hash != node.Artifacts[0].SHA256 || (!local && entry.DownloadInfo.URL != node.Artifacts[0].URL) || (local && !strings.HasPrefix(entry.DownloadInfo.URL, "file://")) {
			return fmt.Errorf("pip graph artifact mismatch for %s", node.Project)
		}
		if node.Project == root.Project {
			required := false
			for _, requirement := range entry.Metadata.RequiresDist {
				if !strings.Contains(requirement, ";") && regexp.MustCompile(`^`+regexp.QuoteMeta(leaf.Project)+`(?:\s|[<>=!~(]|$)`).MatchString(requirement) {
					required = true
				}
			}
			if !required {
				return fmt.Errorf("root does not unconditionally require leaf")
			}
		}
	}
	return nil
}

func runPipGraph(r *caseRun, variant string) error {
	selection, err := loadPipGraph(r.Candidate)
	if err != nil {
		return err
	}
	if selection.Cell.ID != r.Cell.ID || selection.Cell.Executable != r.Cell.Executable || selection.Cell.ManagerVersion != r.Cell.ManagerVersion || selection.Cell.RuntimeVersion != r.Cell.RuntimeVersion {
		return fmt.Errorf("pip graph was resolved for another cell")
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
		run.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + run.Env["PATH"]
		run.Env["SCFW_HOME"] = r.Env["SCFW_HOME"]
		run.Candidate = selection.Roots[index]
		leaf := selection.Leaves[index]
		if r.Spec.Mode == "proxy" {
			run.Env["SCFW_PROXY_ENABLED"] = "1"
		}
		target := filepath.Join(run.Root, "installed")
		if err := os.WriteFile(filepath.Join(run.Root, "constraints.txt"), []byte(leaf.Project+"=="+leaf.Version+"\n"), 0600); err != nil {
			return err
		}
		if _, err := run.Command("git-init", run.Cell.Git, "init", "--quiet"); err != nil {
			return err
		}
		if variant == "already-satisfied" {
			if err := preparePipSatisfied(&run); err != nil {
				return err
			}
			target = ""
		}
		if variant == "empty-requirements" {
			return pipGraphCommand(&run, leaf, "empty", target, false, true, false)
		}
		if err := pipCacheEvidence(&run, "cold", leaf, false); err != nil {
			return err
		}
		if variant == "version-invocations" {
			node := selection.Roots[0]
			if err := writeFinding(&run, "PyPI", node.Project, node.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		if variant == "transitive-block" || variant == "metadata-warm-artifacts-cold" {
			if err := writeFinding(&run, "PyPI", leaf.Project, leaf.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		if variant == "metadata-warm-artifacts-cold" {
			for _, node := range []candidate{run.Candidate, leaf} {
				if _, err := run.Command("prime-metadata", run.Cell.Executable, "index", "versions", node.Project); err != nil {
					return err
				}
			}
			if err := pipCacheEvidence(&run, "metadata-only", leaf, false); err != nil {
				return err
			}
		}
		if strings.HasPrefix(variant, "artifact-warm") || variant == "already-satisfied" {
			if err := pipGraphCommand(&run, leaf, "prime", target, false, false, false); err != nil {
				return err
			}
			if err := pipCacheEvidence(&run, "artifacts-warm", leaf, true); err != nil {
				return err
			}
			if variant == "artifact-warm-offline" {
				directory := filepath.Join(run.Root, "wheelhouse")
				if _, err := run.Command("prime-wheelhouse", run.Cell.Executable, "download", "--only-binary=:all:", "--dest", directory, "--constraint", filepath.Join(run.Root, "constraints.txt"), run.Candidate.Project+"=="+run.Candidate.Version); err != nil {
					return err
				}
				for _, node := range []candidate{run.Candidate, leaf} {
					ev, err := digestFile(filepath.Join(directory, node.Artifacts[0].Name))
					if err != nil {
						return err
					}
					if ev.SHA256 != node.Artifacts[0].SHA256 {
						return fmt.Errorf("primed wheel differs from public discovery")
					}
					run.Result.Evidence["wheelhouse-"+node.Project] = ev
				}
			} else if err := writeFinding(&run, "PyPI", run.Candidate.Project, run.Candidate.Version, "CRITICAL"); err != nil {
				return err
			}
			if variant == "already-satisfied" {
				if err := pipGraphCommand(&run, leaf, "satisfied", target, false, true, false); err != nil {
					return err
				}
				continue
			}
			if err := os.RemoveAll(target); err != nil {
				return err
			}
			offline := variant == "artifact-warm-offline"
			if err := pipGraphCommand(&run, leaf, "reuse", target, !offline && r.Spec.Mode == "resolution", r.Spec.Mode == "proxy", offline); err != nil {
				return err
			}
			run.Result.Observations["coverage_boundary"] = "pip reuses primed bytes without proxy artifact evaluation; --no-index/--find-links is a local wheelhouse source, not a public-registry request or fully offline SCFW verifier"
			continue
		}
		blocked := variant == "transitive-block" || variant == "metadata-warm-artifacts-cold" || variant == "version-invocations" && index == 0
		if err := pipGraphCommand(&run, leaf, "install", target, blocked, false, false); err != nil {
			return err
		}
	}
	return nil
}
func preparePipSatisfied(r *caseRun) error {
	venv := filepath.Join(r.Root, "venv")
	if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", venv); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	python := filepath.Join(venv, "bin", "python")
	if _, err := r.Command("pin-venv-pip", python, "-m", "pip", "install", "--no-deps", "--only-binary=:all:", "pip=="+r.Cell.ManagerVersion); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	r.Cell.Executable = filepath.Join(venv, "bin", "pip")
	r.Cell.Runtime = python
	command, err := r.Command("venv-pip-version", r.Cell.Executable, "--version")
	if err != nil {
		return err
	}
	body, err := os.ReadFile(command.Stdout.Path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(body), "pip "+r.Cell.ManagerVersion+" ") {
		return fmt.Errorf("isolated pip pin mismatch")
	}
	r.Result.Observations["isolated_pip"] = r.Cell.Executable
	return nil
}
func pipCacheEvidence(r *caseRun, label string, leaf candidate, present bool) error {
	script, err := filepath.Abs("testdata/graph_cache/pip/inspect_cache.py")
	if err != nil {
		return err
	}
	args := []string{r.Cell.Runtime, script, r.Env["PIP_CACHE_DIR"]}
	for _, node := range []candidate{r.Candidate, leaf} {
		args = append(args, "https://pypi.org/simple/"+node.Project+"/", node.Artifacts[0].URL)
	}
	command, err := r.Command("cache-"+label, args...)
	if err != nil {
		return err
	}
	var entries map[string]struct {
		Present bool   `json:"present"`
		SHA256  string `json:"sha256"`
	}
	if err := readJSON(command.Stdout.Path, &entries); err != nil {
		return err
	}
	for _, node := range []candidate{r.Candidate, leaf} {
		entry := entries[node.Artifacts[0].URL]
		if entry.Present != present || present && entry.SHA256 != node.Artifacts[0].SHA256 {
			return fmt.Errorf("%s artifact cache state mismatch for %s", label, node.Project)
		}
		if label == "metadata-only" && !entries["https://pypi.org/simple/"+node.Project+"/"].Present {
			return fmt.Errorf("metadata cache not primed for %s", node.Project)
		}
	}
	return nil
}
func pipGraphCommand(r *caseRun, leaf candidate, label, target string, blocked, noTargets, offline bool) error {
	r.Env["SCFW_LOG_FILE"] = filepath.Join(r.Root, label+"-policy.jsonl")
	report := filepath.Join(r.Root, label+"-install.json")
	args := []string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", "pip", "install", "--only-binary=:all:", "--report", report, "-v"}
	if target != "" {
		args = append(args, "--target", target)
	}
	if label == "empty" {
		path := filepath.Join(r.Root, "empty.txt")
		if err := os.WriteFile(path, []byte("# No requirements\n"), 0600); err != nil {
			return err
		}
		args = append(args, "-r", path)
	} else {
		args = append(args, "--constraint", filepath.Join(r.Root, "constraints.txt"), r.Candidate.Project+"=="+r.Candidate.Version)
	}
	if offline {
		args = append(args, "--no-index", "--find-links", filepath.Join(r.Root, "wheelhouse"))
	}
	command, commandErr := r.Command(label, args...)
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if (command.ExitCode != 0) != blocked {
		return fmt.Errorf("pip %s exit%d blocked=%t: %v", label, command.ExitCode, blocked, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("wrong pip inspection mode")
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
		script, err := filepath.Abs("testdata/pip_baseline/inspect_install.py")
		if err != nil {
			return err
		}
		installed := target
		if installed == "" {
			installed = filepath.Join(r.Root, "venv", "lib", "python"+strings.Join(strings.Split(r.Cell.RuntimeVersion, ".")[:2], "."), "site-packages")
		}
		for _, node := range []candidate{r.Candidate, leaf} {
			if blocked && node.Project != blockedNode.Project {
				continue
			}
			state, err := r.Command("state-"+label, r.Cell.Runtime, "-I", script, installed, node.Project, node.Module)
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
	if !blocked {
		var graph pipGraphReport
		if err := readJSON(report, &graph); err != nil {
			return err
		}
		if label == "empty" || label == "satisfied" {
			if len(graph.Install) != 0 {
				return fmt.Errorf("no-target command installed packages")
			}
		} else if err := matchPipGraph(graph, r.Candidate, leaf, offline); err != nil {
			return err
		}
		if err := r.Keep(label+"-report-"+filepath.Base(r.Root), report); err != nil {
			return err
		}
	}
	if !blocked && !noTargets && !offline {
		if err := pipCacheEvidence(r, label+"-after", leaf, true); err != nil {
			return err
		}
	}
	if err := assertCleanup(r, string(stderr)); err != nil {
		return err
	}
	return snapshotGraphEvidence(r, label+"-cleanup-"+filepath.Base(r.Root), filepath.Join(r.Root, "cleanup.json"))
}
func TestHarnessPipGraph(t *testing.T) {
	root := candidate{Project: "root", Version: "1", Artifacts: []artifact{{URL: "https://registry/root.whl", SHA256: "root-hash"}}}
	leaf := candidate{Project: "leaf", Version: "2", Artifacts: []artifact{{URL: "https://registry/leaf.whl", SHA256: "leaf-hash"}}}
	var fixtures map[string]pipGraphReport
	if err := readJSON("testdata/graph_cache/pip/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	for name, report := range fixtures {
		err := matchPipGraph(report, root, leaf, false)
		if (err == nil) != (name == "required") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestHarnessPipCacheUsesConfiguredRuntime(t *testing.T) {
	fixture, err := os.ReadFile("testdata/graph_cache/pip/cache_runtime.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, adjacent := range []bool{false, true} {
		t.Run(fmt.Sprintf("adjacent-python-%t", adjacent), func(t *testing.T) {
			root := t.TempDir()
			env, err := isolatedEnvironment(root)
			if err != nil {
				t.Fatal(err)
			}
			runtime := filepath.Join(root, "selected runtime", "python3")
			launcher := filepath.Join(root, "launchers", "pip")
			paths := []string{runtime, launcher}
			if adjacent {
				paths = append(paths, filepath.Join(filepath.Dir(launcher), "python"))
			}
			for _, path := range paths {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, fixture, 0700); err != nil {
					t.Fatal(err)
				}
			}
			selected := candidate{Project: "root", Artifacts: []artifact{{URL: "https://registry/root.whl", SHA256: strings.Repeat("1", 64)}}}
			leaf := candidate{Project: "leaf", Artifacts: []artifact{{URL: "https://registry/leaf.whl", SHA256: strings.Repeat("2", 64)}}}
			env["SCFW_TEST_PYTHON_RUNTIME"] = runtime
			env["SCFW_TEST_ROOT_SHA"] = selected.Artifacts[0].SHA256
			env["SCFW_TEST_LEAF_SHA"] = leaf.Artifacts[0].SHA256
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r := &caseRun{Context: ctx, Cell: cell{Executable: launcher, Runtime: runtime}, Candidate: selected, Root: root, WorkDir: filepath.Join(root, "work"), Env: env, Result: &result{}}
			if err := pipCacheEvidence(r, "warm", leaf, true); err != nil {
				t.Fatal(err)
			}
			if len(r.Result.Commands) != 1 || r.Result.Commands[0].Argv[0] != runtime {
				t.Fatalf("cache evidence did not record configured runtime: %+v", r.Result.Commands)
			}
		})
	}
}
