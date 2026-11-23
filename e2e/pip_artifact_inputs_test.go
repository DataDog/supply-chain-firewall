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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"text/template"
	"time"
)

type pipInputSelection struct {
	Graph         candidate       `json:"graph"`
	Sdist         candidate       `json:"sdist"`
	Extra         candidate       `json:"extra"`
	ExtrasReport  fileEvidence    `json:"extras_report"`
	ExtrasCommand commandEvidence `json:"extras_command"`
}

func init() {
	discoverers["pip-inputs"] = discoverPipInputs
	revalidators["pip-inputs"] = revalidatePipInputs
	for _, mode := range []string{"resolution", "proxy"} {
		variants := []string{"wheel", "sdist", "direct-url", "nested-constraints", "extras-markers"}
		if mode == "proxy" {
			variants = append(variants, "download-wheel", "download-sdist", "build-sdist", "find-links", "remote-requirements")
		}
		for _, variant := range variants {
			for _, blocked := range []bool{false, true} {
				id, profile, action := "PIP-01", "public-pypi", "allow"
				if strings.Contains(variant, "download") || variant == "build-sdist" || variant == "find-links" || variant == "remote-requirements" {
					id = "PIP-02"
				}
				if variant == "remote-requirements" {
					profile = "public-pypi-controlled-requirement-documents"
				}
				if blocked {
					action = "block"
				}
				suites["pip-artifact-inputs"] = append(suites["pip-artifact-inputs"], scenario{Scenario: id, Variant: mode + "-" + variant + "-" + action, Manager: "pip", Mode: mode, Backend: "local", RegistryProfile: profile, DiscoveryKey: "pip-inputs", Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runPipInput(r, variant, blocked) }})
			}
		}
	}
}

func discoverPipInputs(ctx context.Context, c cell, output string) (candidate, error) {
	graph, err := discoverPipGraph(ctx, c, filepath.Join(output, "graph"))
	if err != nil {
		return candidate{}, err
	}
	selected, err := loadPipGraph(graph)
	if err != nil {
		return candidate{}, err
	}
	root := selected.Roots[0]
	var metadata pypiMetadata
	evidence, err := fetchJSON(ctx, "https://pypi.org/pypi/"+root.Project+"/"+root.Version+"/json", filepath.Join(output, "root-release.json"), &metadata)
	if err != nil {
		return candidate{}, err
	}
	selection := pipInputSelection{Graph: graph}
	for _, file := range metadata.URLs {
		if !file.Yanked && strings.HasSuffix(file.Filename, ".tar.gz") && file.UploadTime.Before(root.ObservedAt.Add(-48*time.Hour)) && strings.HasPrefix(file.URL, "https://files.pythonhosted.org/") && len(file.Digests.SHA256) == 64 {
			selection.Sdist = pipGraphCandidate(root.Project, root.Version, root.Module, file, evidence, root.ObservedAt)
		}
	}
	if selection.Sdist.Project == "" {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("selected public release has no eligible sdist"))
	}
	directory := filepath.Join(output, "extras")
	env, err := isolatedEnvironment(directory)
	if err != nil {
		return candidate{}, err
	}
	reportPath := filepath.Join(directory, "report.json")
	selection.ExtrasCommand, err = runCommand(ctx, filepath.Join(directory, "command"), env, filepath.Join(directory, "work"), c.Executable, "install", "--dry-run", "--ignore-installed", "--only-binary=:all:", "--report", reportPath, root.Project+"[unidecode]=="+root.Version)
	if err != nil {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
	}
	var report pipGraphReport
	if err := readJSON(reportPath, &report); err != nil {
		return candidate{}, err
	}
	for _, entry := range report.Install {
		if !strings.EqualFold(entry.Metadata.Name, "Unidecode") {
			continue
		}
		var extra pypiMetadata
		evidence, err := fetchJSON(ctx, "https://pypi.org/pypi/Unidecode/"+entry.Metadata.Version+"/json", filepath.Join(directory, "extra.json"), &extra)
		if err != nil {
			return candidate{}, err
		}
		for _, file := range extra.URLs {
			if file.URL == entry.DownloadInfo.URL && eligiblePipGraphFile(file, c, root.ObservedAt) {
				selection.Extra = pipGraphCandidate(extra.Info.Name, entry.Metadata.Version, "unidecode", file, evidence, root.ObservedAt)
			}
		}
	}
	if selection.Extra.Project == "" {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("extra did not select eligible public Unidecode wheel"))
	}
	if err := matchPipInputReport(report, []candidate{root, selected.Leaves[0], selection.Extra}); err != nil {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", err)
	}
	selection.ExtrasReport, err = digestFile(reportPath)
	if err != nil {
		return candidate{}, err
	}
	path := filepath.Join(output, "selection.json")
	if err := writeJSON(path, selection); err != nil {
		return candidate{}, err
	}
	digest, err := digestFile(path)
	root.Selection = &digest
	root.Property = "public-wheel-sdist-requirement-inputs"
	return root, err
}
func loadPipInputs(c candidate) (pipInputSelection, pipGraphSelection, error) {
	var selection pipInputSelection
	var graph pipGraphSelection
	if c.Selection == nil {
		return selection, graph, fmt.Errorf("missing pip inputs selection")
	}
	if err := verifyGraphFile(*c.Selection); err != nil {
		return selection, graph, err
	}
	if err := readJSON(c.Selection.Path, &selection); err != nil {
		return selection, graph, err
	}
	graph, err := loadPipGraph(selection.Graph)
	if err != nil {
		return selection, graph, err
	}
	if c.Project != graph.Roots[0].Project || c.Version != graph.Roots[0].Version || selection.Sdist.Project != c.Project || selection.Sdist.Version != c.Version || !strings.EqualFold(selection.Extra.Project, "Unidecode") {
		return selection, graph, fmt.Errorf("invalid pip inputs identity")
	}
	for _, node := range []candidate{selection.Sdist, selection.Extra} {
		if err := validateCandidate(node, time.Now().UTC()); err != nil {
			return selection, graph, err
		}
	}
	if err := verifyGraphFile(selection.ExtrasReport); err != nil {
		return selection, graph, err
	}
	var report pipGraphReport
	if err := readJSON(selection.ExtrasReport.Path, &report); err != nil {
		return selection, graph, err
	}
	return selection, graph, matchPipInputReport(report, []candidate{graph.Roots[0], graph.Leaves[0], selection.Extra})
}
func revalidatePipInputs(ctx context.Context, c candidate, output string) error {
	selection, _, err := loadPipInputs(c)
	if err != nil {
		return err
	}
	if err := revalidatePipGraph(ctx, selection.Graph, filepath.Join(output, "graph")); err != nil {
		return err
	}
	for index, node := range []candidate{selection.Sdist, selection.Extra} {
		if err := revalidatePyPI(ctx, node, filepath.Join(output, fmt.Sprint(index))); err != nil {
			return err
		}
	}
	return nil
}
func matchPipInputReport(report pipGraphReport, nodes []candidate) error {
	if len(report.Install) != len(nodes) {
		return fmt.Errorf("pip selected %d distributions, want %d", len(report.Install), len(nodes))
	}
	seen := map[string]bool{}
	for _, entry := range report.Install {
		found := false
		for _, node := range nodes {
			if !strings.EqualFold(entry.Metadata.Name, node.Project) {
				continue
			}
			hash := entry.DownloadInfo.ArchiveInfo.Hashes["sha256"]
			if hash == "" {
				hash = strings.TrimPrefix(entry.DownloadInfo.ArchiveInfo.Hash, "sha256=")
			}
			if seen[node.Project] || entry.Metadata.Version != node.Version || entry.DownloadInfo.URL != node.Artifacts[0].URL || hash != node.Artifacts[0].SHA256 {
				return fmt.Errorf("wrong pip input artifact for %s", node.Project)
			}
			found, seen[node.Project] = true, true
		}
		if !found {
			return fmt.Errorf("unexpected selected distribution %s", entry.Metadata.Name)
		}
	}
	return nil
}
func pipInputDocument(name string, values map[string]string) ([]byte, error) {
	t, err := template.ParseFiles(filepath.Join("testdata/pip_inputs/artifacts", name+".tmpl"))
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	err = t.Execute(&body, values)
	return body.Bytes(), err
}
func runPipInput(r *caseRun, variant string, blocked bool) error {
	selection, graph, err := loadPipInputs(r.Candidate)
	if err != nil {
		return err
	}
	if graph.Cell.ID != r.Cell.ID || graph.Cell.ManagerVersion != r.Cell.ManagerVersion || graph.Cell.RuntimeVersion != r.Cell.RuntimeVersion || graph.Cell.Executable != r.Cell.Executable {
		return fmt.Errorf("selection resolved for another pip cell")
	}
	root, leaf := graph.Roots[0], graph.Leaves[0]
	r.Result.Observations["selection"] = r.Candidate.Selection
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	if _, err := r.Command("git-init", r.Cell.Git, "init", "--quiet"); err != nil {
		return err
	}
	nodes := []candidate{root}
	command, artifactKind := "install", "wheel"
	if variant == "sdist" || variant == "download-sdist" || variant == "build-sdist" {
		nodes[0] = selection.Sdist
		artifactKind = "sdist"
	}
	if strings.HasPrefix(variant, "download-") {
		command = "download"
	}
	if variant == "build-sdist" {
		command = "wheel"
	}
	if command == "install" {
		nodes = append(nodes, leaf)
	}
	if variant == "extras-markers" {
		nodes = append(nodes, selection.Extra)
	}
	blockedNode := nodes[0]
	if variant == "nested-constraints" || variant == "extras-markers" || variant == "remote-requirements" {
		blockedNode = leaf
	}
	if blocked {
		if err := writeFinding(r, "PyPI", blockedNode.Project, blockedNode.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	target, report := filepath.Join(r.Root, "output with spaces"), filepath.Join(r.Root, "install.json")
	args := []string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--", "pip", command, "--no-cache-dir"}
	if command == "install" {
		args = append(args, "--target", target, "--report", report)
	} else if command == "download" {
		args = append(args, "--dest", target)
	} else {
		args = append(args, "--wheel-dir", target)
	}
	if len(nodes) == 1 {
		args = append(args, "--no-deps")
	}
	if artifactKind == "sdist" {
		args = append(args, "--no-binary="+root.Project)
	} else {
		args = append(args, "--only-binary=:all:")
	}
	values := map[string]string{"Root": root.Project, "Version": root.Version, "OldVersion": graph.Roots[1].Version, "Leaf": leaf.Project, "LeafVersion": leaf.Version, "Extra": selection.Extra.Project, "ExtraVersion": selection.Extra.Version, "URL": root.Artifacts[0].URL, "SHA256": root.Artifacts[0].SHA256}
	var documentRequests atomic.Int32
	constraints := filepath.Join(r.Root, "pins.txt")
	if err := os.WriteFile(constraints, []byte(leaf.Project+"=="+leaf.Version+"\n"+selection.Extra.Project+"=="+selection.Extra.Version+"\n"), 0600); err != nil {
		return err
	}
	args = append(args, "--constraint", constraints)
	switch variant {
	case "direct-url":
		args = append(args, root.Project+" @ "+root.Artifacts[0].URL+"#sha256="+root.Artifacts[0].SHA256)
	case "nested-constraints", "extras-markers":
		for _, name := range []string{"requirements.txt", "nested.txt", "constraints.txt", "extras.txt"} {
			body, err := pipInputDocument(name, values)
			if err != nil {
				return err
			}
			path := filepath.Join(r.WorkDir, name)
			if err := os.WriteFile(path, body, 0600); err != nil {
				return err
			}
			if err := r.Keep(name, path); err != nil {
				return err
			}
		}
		name := "requirements.txt"
		if variant == "extras-markers" {
			name = "extras.txt"
		}
		args = append(args, "-r", filepath.Join(r.WorkDir, name))
	case "remote-requirements":
		body, err := pipInputDocument("remote.txt", values)
		if err != nil {
			return err
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/requirements.txt" {
				http.NotFound(w, request)
				return
			}
			documentRequests.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
		}))
		defer server.Close()
		defer func() { r.Result.Observations["requirement_document_requests"] = documentRequests.Load() }()
		args = append(args, "-r", server.URL+"/requirements.txt")
		r.Result.Observations["controlled_origin_reason"] = "Only the custom requirement document is local; all artifacts remain on public PyPI. This case does not exercise redirect or compression transport."
	case "find-links":
		args = append(args, "--no-index", "--find-links", "https://pypi.org/simple/"+root.Project+"/", "--find-links", "https://pypi.org/simple/"+leaf.Project+"/", root.Project+"=="+root.Version)
	default:
		args = append(args, root.Project+"=="+root.Version)
	}
	ev, commandErr := r.Command("scfw", args...)
	if ev.TimedOut || ev.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %v", commandErr))
	}
	if (ev.ExitCode != 0) != blocked {
		return fmt.Errorf("%s exit=%d blocked=%t: %v", variant, ev.ExitCode, blocked, commandErr)
	}
	if variant == "remote-requirements" && documentRequests.Load() == 0 {
		return fmt.Errorf("pip did not fetch remote requirements")
	}
	stderr, err := os.ReadFile(ev.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") {
		return fmt.Errorf("wrong inspection mode")
	}
	expected := nodes
	if blocked {
		expected = []candidate{blockedNode}
	}
	if err := assertGraphPolicy(r, expected, blocked, false); err != nil {
		return err
	}
	if command == "install" {
		for _, node := range nodes {
			if blocked && node.Project != blockedNode.Project {
				continue
			}
			if err := assertPipInputInstalled(r, target, node, !blocked); err != nil {
				return err
			}
		}
		if !blocked {
			var actual pipGraphReport
			if err := readJSON(report, &actual); err != nil {
				return err
			}
			if err := matchPipInputReport(actual, nodes); err != nil {
				return err
			}
			if err := r.Keep("install-report", report); err != nil {
				return err
			}
		}
	} else if err := assertPipInputOutput(r, target, nodes[0], command == "wheel", blocked); err != nil {
		return err
	}
	r.Result.Observations["source_artifacts"] = nodes
	r.Result.Observations["sdist_boundary"] = "Resolution may execute build metadata before evaluation. Proxy observes target and actual build dependency requests; policy records are not rollback or proof that no metadata code ran."
	return assertCleanup(r, string(stderr))
}
func assertPipInputInstalled(r *caseRun, target string, node candidate, present bool) error {
	script, err := filepath.Abs("testdata/pip_baseline/inspect_install.py")
	if err != nil {
		return err
	}
	ev, err := r.Command("state-"+node.Project, r.Cell.Runtime, "-I", script, target, node.Project, node.Module)
	if err != nil {
		return err
	}
	var state struct {
		Present, Imported bool
		Version           string
	}
	if err := readJSON(ev.Stdout.Path, &state); err != nil {
		return err
	}
	if state.Present != present || present && (state.Version != node.Version || !state.Imported) {
		return fmt.Errorf("unexpected installed %s: %+v", node.Project, state)
	}
	return nil
}
func assertPipInputOutput(r *caseRun, target string, node candidate, built, blocked bool) error {
	paths, err := filepath.Glob(filepath.Join(target, "*"))
	if err != nil {
		return err
	}
	if blocked {
		if len(paths) != 0 {
			return fmt.Errorf("blocked command produced output artifacts: %v", paths)
		}
		return nil
	}
	if len(paths) != 1 {
		return fmt.Errorf("expected exactly one output artifact: %v", paths)
	}
	evidence, err := digestFile(paths[0])
	if err != nil {
		return err
	}
	r.Result.Evidence["output-artifact"] = evidence
	if !built {
		if filepath.Base(paths[0]) != node.Artifacts[0].Name || evidence.SHA256 != node.Artifacts[0].SHA256 {
			return fmt.Errorf("download differs from public artifact")
		}
		return nil
	}
	script, err := filepath.Abs("testdata/pip_inputs/artifacts/inspect_wheel.py")
	if err != nil {
		return err
	}
	_, err = r.Command("built-wheel-identity", r.Cell.Runtime, "-I", script, paths[0], node.Project, node.Version)
	return err
}
func TestHarnessPipInputReport(t *testing.T) {
	root := candidate{Project: "root", Version: "1", Artifacts: []artifact{{URL: "https://registry/root.whl", SHA256: "root-hash"}}}
	leaf := candidate{Project: "leaf", Version: "2", Artifacts: []artifact{{URL: "https://registry/leaf.whl", SHA256: "leaf-hash"}}}
	var fixtures map[string]pipGraphReport
	if err := readJSON("testdata/graph_cache/pip/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	for name, report := range fixtures {
		err := matchPipInputReport(report, []candidate{root, leaf})
		// This checker verifies the selected set/artifacts; dependency-edge semantics
		// are already verified by the parent graph selection.
		valid := name == "required" || name == "optional" || name == "explicit-leaf"
		if (err == nil) != valid {
			t.Errorf("%s: %v", name, err)
		}
	}
}
