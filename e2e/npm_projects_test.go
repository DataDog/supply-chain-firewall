//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"
)

type npmProjectSelection struct{ Graph, Direct candidate }
type npmProjectOptions struct {
	variant string
	block   bool
}
type npmProjectPackage struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Local   bool   `json:"local"`
}

func init() {
	discoverers["npm-projects"] = discoverNPMProjects
	revalidators["npm-projects"] = revalidateNPMProjects
	add := func(id, variant, mode, key, capability string, block bool) {
		suites["npm-projects"] = append(suites["npm-projects"], scenario{Scenario: id, Variant: mode + "-" + variant + map[bool]string{false: "-allow", true: "-block"}[block], Manager: "npm", Mode: mode, Backend: "local", RegistryProfile: "public-npm", DiscoveryKey: key, Capabilities: []string{capability}, Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runNPMProject(r, npmProjectOptions{variant, block}) }})
	}
	for _, mode := range []string{"resolution", "proxy"} {
		for _, variant := range []string{"manifest-no-lock", "manifest-lock", "dev", "production", "production-no-save", "dev-no-save", "prefix-separate-no-save", "prefix-equals-no-save", "global-production", "duplicates", "upgrade", "downgrade", "workspace", "workspace-unhoisted", "workspace-selected", "workspace-member", "workspace-member-disabled", "workspace-selected-production", "local", "marker", "ci"} {
			id := "NPM-02"
			if slices.Contains([]string{"workspace", "workspace-unhoisted", "workspace-selected", "workspace-member", "workspace-member-disabled", "workspace-selected-production", "local", "marker"}, variant) {
				id = "NPM-03"
			}
			if variant == "ci" {
				id = "NPM-04"
			}
			for _, block := range []bool{false, true} {
				add(id, variant, mode, "npm-projects", "npm-projects-v7", block)
			}
		}
		for _, variant := range []string{"help", "version", "dry-run", "unresolved", "final-failure"} {
			id := "NPM-04"
			if variant == "unresolved" || variant == "final-failure" {
				id = "CORE-14"
			}
			add(id, variant, mode, "npm-projects", "npm-projects-v7", false)
		}
		add("CORE-11", "pre7-install", mode, "npm-old", "npm-resolution-pre7", true)
		add("CORE-11", "pre7-version", mode, "npm-old", "npm-resolution-pre7", false)
	}
}

func discoverNPMProjects(ctx context.Context, c cell, output string) (candidate, error) {
	graph, err := discoverNPMGraph(ctx, c, filepath.Join(output, "graph"))
	if err != nil {
		return candidate{}, err
	}
	selection, err := loadNPMGraph(graph)
	if err != nil {
		return candidate{}, err
	}
	direct, err := discoverNPMOld(ctx, c, filepath.Join(output, "direct"), "npm-old")
	if err != nil {
		return candidate{}, err
	}
	if direct.Project != selection.Leaves[0].Project || direct.Version == selection.Leaves[0].Version {
		return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("duplicate-version fixture needs an independent version of the graph leaf"))
	}
	path := filepath.Join(output, "projects.json")
	if err := writeJSON(path, npmProjectSelection{graph, direct}); err != nil {
		return candidate{}, err
	}
	digest, err := digestFile(path)
	selected := direct
	selected.Selection = &digest
	selected.Property = "npm-project-selection"
	return selected, err
}
func loadNPMProjects(c candidate) (npmProjectSelection, npmGraphSelection, error) {
	var selection npmProjectSelection
	if c.Selection == nil {
		return selection, npmGraphSelection{}, fmt.Errorf("missing project selection")
	}
	if err := verifyGraphFile(*c.Selection); err != nil {
		return selection, npmGraphSelection{}, err
	}
	if err := readJSON(c.Selection.Path, &selection); err != nil {
		return selection, npmGraphSelection{}, err
	}
	graph, err := loadNPMGraph(selection.Graph)
	if err == nil {
		err = validateCandidate(selection.Direct, time.Now().UTC())
	}
	if err == nil && (selection.Direct.Project != c.Project || selection.Direct.Version != c.Version) {
		err = fmt.Errorf("project candidate differs from retained selection")
	}
	return selection, graph, err
}
func revalidateNPMProjects(ctx context.Context, c candidate, output string) error {
	selection, _, err := loadNPMProjects(c)
	if err != nil {
		return err
	}
	if err := revalidateNPMGraph(ctx, selection.Graph, filepath.Join(output, "graph")); err != nil {
		return err
	}
	return revalidateNPM(ctx, selection.Direct, filepath.Join(output, "direct"))
}

func npmProjectFiles(r *caseRun, variant string, direct, root candidate) (map[string]json.RawMessage, error) {
	if npmGlobalVariant(variant) {
		return npmGlobalFiles(r, variant, direct, root)
	}
	shape := variant
	switch variant {
	case "manifest-no-lock", "manifest-lock", "ci", "help", "version", "dry-run", "unresolved", "pre7-install", "pre7-version":
		shape = "manifest"
	case "production", "production-no-save", "dev-no-save", "prefix-separate-no-save", "prefix-equals-no-save":
		shape = "dev"
	case "workspace-selected", "workspace-member":
		shape = "workspace-two"
	case "workspace-member-disabled":
		shape = "workspace-disabled"
	case "workspace-selected-production":
		shape = "workspace-production"
	case "upgrade", "downgrade":
		shape = "graph"
	case "final-failure":
		shape = "marker"
	}
	marker, err := filepath.Abs("testdata/npm_projects/final_install.cjs")
	if err != nil {
		return nil, err
	}
	lifecycle, err := json.Marshal("node " + strconv.Quote(marker))
	if err != nil {
		return nil, err
	}
	tmpl, err := template.ParseFiles("testdata/npm_projects/projects.json.tmpl")
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err := tmpl.Execute(&body, map[string]any{"Direct": direct, "Root": root, "Lifecycle": string(lifecycle)}); err != nil {
		return nil, err
	}
	var fixtures map[string]map[string]json.RawMessage
	if err := json.Unmarshal(body.Bytes(), &fixtures); err != nil {
		return nil, err
	}
	files, ok := fixtures[shape]
	if !ok {
		return nil, fmt.Errorf("unknown project shape %s", shape)
	}
	for path, body := range files {
		destination := filepath.Join(r.WorkDir, path)
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(destination, body, 0600); err != nil {
			return nil, err
		}
	}
	r.Env["SCFW_E2E_FINAL_PROJECT"] = r.WorkDir
	if variant == "final-failure" {
		r.Env["SCFW_E2E_FINAL_FAILURE"] = "1"
	}
	return files, nil
}

func prepareNPMProjectCase(r *caseRun, variant string, direct, initial candidate) ([]string, map[string][]byte, []npmProjectPackage, error) {
	prefixed := variant == "prefix-separate-no-save" || variant == "prefix-equals-no-save"
	if prefixed {
		r.WorkDir = filepath.Join(r.Root, "prefixed project with spaces")
		if err := os.MkdirAll(r.WorkDir, 0700); err != nil {
			return nil, nil, nil, err
		}
	}
	if _, err := prepareNPMProject(r); err != nil {
		return nil, nil, nil, err
	}
	files, err := npmProjectFiles(r, variant, direct, initial)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := os.Remove(filepath.Join(r.WorkDir, "package-lock.json")); err != nil {
		return nil, nil, nil, err
	}
	args := []string{"install", "--ignore-scripts", "--loglevel=http"}
	if prefixed || variant == "manifest-lock" || variant == "ci" || variant == "workspace-unhoisted" || variant == "workspace-member-disabled" || variant == "production-no-save" || variant == "dev-no-save" || variant == "upgrade" || variant == "downgrade" {
		bootstrap := []string{r.Cell.Executable, "install", "--ignore-scripts"}
		if prefixed || variant == "manifest-lock" || variant == "ci" || variant == "workspace-unhoisted" || variant == "workspace-member-disabled" || variant == "production-no-save" || variant == "dev-no-save" {
			bootstrap = append(bootstrap, "--package-lock-only")
		}
		if _, err := r.Command("project-bootstrap", bootstrap...); err != nil {
			return nil, nil, nil, classified("INFRASTRUCTURE_FAILURE", err)
		}
	}
	if npmGlobalVariant(variant) {
		if err := prepareNPMGlobalState(r, variant, initial); err != nil {
			return nil, nil, nil, err
		}
	}
	if variant == "workspace-member-disabled" {
		var lock npmGraphLock
		if err := readJSON(filepath.Join(r.WorkDir, "package-lock.json"), &lock); err != nil {
			return nil, nil, nil, err
		}
		version := lock.Packages["node_modules/"+direct.Project].Version
		if version == "" || version == direct.Version {
			return nil, nil, nil, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("workspace root must lock a competing version of %s", direct.Project))
		}
	}
	if variant == "workspace-unhoisted" {
		path := filepath.Join(r.WorkDir, "packages/member/package.json")
		var manifest map[string]any
		if err := readJSON(path, &manifest); err != nil {
			return nil, nil, nil, err
		}
		manifest["dependencies"].(map[string]any)[initial.Project] = ">=" + initial.Version + " <=" + direct.Version
		if err := writeJSON(path, manifest); err != nil {
			return nil, nil, nil, err
		}
	}
	switch variant {
	case "production":
		args = append(args, "--production")
	case "production-no-save", "dev-no-save", "prefix-separate-no-save", "prefix-equals-no-save":
		saveType := "--save-prod"
		if variant == "dev-no-save" {
			saveType = "--save-dev"
		}
		args = append(args, initial.Project+"@"+initial.Version, saveType, "--no-save", "--omit=dev")
	case "global-production":
		globalTarget := direct
		r.Env["NODE_ENV"] = "production"
		r.Env["npm_config_prefix"] = filepath.Join(r.Root, "global-prefix")
		if err := os.MkdirAll(filepath.Join(r.Env["npm_config_prefix"], "lib", "node_modules"), 0700); err != nil {
			return nil, nil, nil, err
		}
		args = append(args, "-g", globalTarget.Project+"@"+globalTarget.Version)
	case "global-workspace-member", "global-self":
		args = append(args, npmGlobalArgs(variant, initial)...)
	case "workspace-member-disabled":
		args = append(args, "--workspaces=false")
	case "workspace-selected":
		args = append(args, "--workspace=scfw-e2e-member")
	case "workspace-selected-production":
		args = append(args, "--workspace=scfw-e2e-member", "--production")
	case "ci":
		args[0] = "ci"
	case "help":
		args = []string{"--help"}
	case "version", "pre7-version":
		args = []string{"--version"}
	case "dry-run":
		args = append(args, "--dry-run")
	case "marker", "final-failure":
		args = []string{"install", "--loglevel=http"}
	case "unresolved":
		args = append(args, direct.Project+"@0.0.0-scfw-e2e-unpublished")
	}
	if prefixed {
		if variant == "prefix-separate-no-save" {
			args = append(args, "--prefix", r.WorkDir)
		} else {
			args = append(args, "--prefix="+r.WorkDir)
		}
	}
	paths := []string{"package-lock.json", "final-install.marker"}
	if variant == "workspace-member" || variant == "workspace-member-disabled" || variant == "global-workspace-member" {
		paths = append(paths, "packages/member/package-lock.json")
	}
	for path := range files {
		paths = append(paths, path)
	}
	before, err := npmProjectSnapshot(r, "before", paths)
	if err != nil {
		return nil, nil, nil, err
	}
	state, err := npmProjectState(r, "before")
	return args, before, state, err
}
func npmProjectSnapshot(r *caseRun, label string, paths []string) (map[string][]byte, error) {
	snapshot := map[string][]byte{}
	for _, path := range paths {
		body, err := os.ReadFile(filepath.Join(r.WorkDir, path))
		if os.IsNotExist(err) {
			snapshot[path] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		snapshot[path] = body
	}
	path := filepath.Join(r.Root, "project-"+label+".json")
	if err := writeJSON(path, snapshot); err != nil {
		return nil, err
	}
	return snapshot, r.Keep("project-"+label+"-"+filepath.Base(r.Root), path)
}
func npmProjectState(r *caseRun, label string) ([]npmProjectPackage, error) {
	script, err := filepath.Abs("testdata/npm_projects/inspect_project.cjs")
	if err != nil {
		return nil, err
	}
	directory := r.WorkDir
	if prefix := r.Env["npm_config_prefix"]; prefix != "" {
		directory = filepath.Join(prefix, "lib")
	}
	args := []string{r.Cell.Runtime, script, directory}
	if strings.Contains(r.Spec.Variant, "-workspace-member-") || strings.Contains(r.Spec.Variant, "-workspace-unhoisted-") {
		args = append(args, "packages/member")
	}
	if strings.Contains(r.Spec.Variant, "-global-self-") {
		args = append(args, "node_modules/scfw-e2e-global-source")
	}
	command, err := r.Command("state-"+label, args...)
	if err != nil {
		return nil, err
	}
	var state []npmProjectPackage
	err = readJSON(command.Stdout.Path, &state)
	r.Result.Observations[label+"-packages-"+filepath.Base(r.Root)] = state
	return state, err
}

func runNPMProject(r *caseRun, options npmProjectOptions) error {
	production := options.variant == "production" || options.variant == "workspace-selected-production" || options.variant == "dev-no-save"
	direct, initial, target := r.Candidate, r.Candidate, r.Candidate
	var graph npmGraphSelection
	var candidates []candidate
	if r.Spec.DiscoveryKey == "npm-projects" {
		selection, selected, err := loadNPMProjects(r.Candidate)
		if err != nil {
			return err
		}
		graph = selected
		if graph.Cell.ID != r.Cell.ID || graph.Cell.ManagerVersion != r.Cell.ManagerVersion {
			return fmt.Errorf("project graph belongs to another cell")
		}
		direct, initial, target = selection.Direct, graph.Roots[0], selection.Direct
		candidates = append(append([]candidate{direct}, graph.Roots...), graph.Leaves...)
		if options.variant == "upgrade" {
			initial, target = graph.Roots[1], graph.Roots[0]
		}
		if options.variant == "downgrade" {
			initial, target = graph.Roots[0], graph.Roots[1]
		}
		if options.variant == "dev" || options.variant == "production-no-save" || options.variant == "prefix-separate-no-save" || options.variant == "prefix-equals-no-save" || production && options.block {
			target = graph.Roots[0]
		}
		if options.variant == "duplicates" {
			target = graph.Leaves[0]
		}
		if npmGlobalVariant(options.variant) {
			initial, target = graph.Leaves[0], graph.Leaves[0]
		}
		if options.variant == "workspace-unhoisted" {
			initial, target = graph.Leaves[0], graph.Leaves[0]
		}
	} else {
		candidates = []candidate{direct}
	}
	r.Result.Observations["selected_packages"] = candidates
	// Run the same command natively in a separate project and cache. Its observed
	// installation is the target-selection oracle, not SCFW's policy report.
	native := *r
	native.Root = filepath.Join(r.Root, "native")
	native.WorkDir = filepath.Join(native.Root, "work")
	var err error
	native.Env, err = isolatedEnvironment(native.Root)
	if err != nil {
		return err
	}
	args, _, nativeBefore, err := prepareNPMProjectCase(&native, options.variant, direct, initial)
	if err != nil {
		return err
	}
	if options.variant == "upgrade" || options.variant == "downgrade" {
		args = append(args, target.Project+"@"+target.Version)
	}
	nativeRoot := native.WorkDir
	if options.variant == "workspace-member" || options.variant == "workspace-member-disabled" || options.variant == "global-workspace-member" {
		native.WorkDir = filepath.Join(nativeRoot, "packages/member")
	}
	nativeCommand, nativeErr := native.Command("native-command", append([]string{r.Cell.Executable}, args...)...)
	native.WorkDir = nativeRoot
	if nativeCommand.TimedOut || nativeCommand.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("native launch: %w", nativeErr))
	}
	nativeFailure := options.variant == "unresolved" || options.variant == "final-failure"
	if options.variant == "help" {
		stdout, err := os.ReadFile(nativeCommand.Stdout.Path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(stdout), "npm <command>") || nativeCommand.ExitCode > 1 {
			return fmt.Errorf("native npm help did not print usage")
		}
		// npm7.0.0 prints its normal usage with exit1; preserve its native exit.
		nativeFailure = nativeCommand.ExitCode == 1
	}
	if (nativeCommand.ExitCode != 0) != nativeFailure {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("native command exit %d: %v", nativeCommand.ExitCode, nativeErr))
	}
	expected, err := npmProjectState(&native, "after")
	if err != nil {
		return err
	}
	if options.variant == "workspace-unhoisted" && !slices.ContainsFunc(expected, func(pkg npmProjectPackage) bool {
		return pkg.Name == target.Project && pkg.Version == target.Version && strings.HasPrefix(pkg.Path, "packages/member/node_modules/")
	}) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("native npm did not preserve the unhoisted locked version"))
	}
	if err := npmProjectArtifacts(&native, expected, candidates); err != nil {
		return err
	}
	args, before, previous, err := prepareNPMProjectCase(r, options.variant, direct, initial)
	if err != nil {
		return err
	}
	if options.variant == "upgrade" || options.variant == "downgrade" {
		args = append(args, target.Project+"@"+target.Version)
	}
	if !reflect.DeepEqual(previous, nativeBefore) {
		return fmt.Errorf("native and wrapped starting installations differ")
	}
	if options.block || slices.Contains([]string{"help", "version", "dry-run", "pre7-version"}, options.variant) {
		if err := writeFinding(r, "npm", target.Project, target.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	projectRoot := r.WorkDir
	if options.variant == "workspace-member" || options.variant == "workspace-member-disabled" || options.variant == "global-workspace-member" {
		r.WorkDir = filepath.Join(projectRoot, "packages/member")
	}
	command, commandErr := r.Command("scfw", append([]string{r.Binary, "run", "--error-on-block", "--", "npm"}, args...)...)
	r.WorkDir = projectRoot
	if command.TimedOut || command.ExitCode < 0 {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("SCFW launch: %w", commandErr))
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if slices.Contains([]string{"help", "version", "pre7-version"}, options.variant) {
		nativeOutput, err := os.ReadFile(nativeCommand.Stdout.Path)
		if err != nil {
			return err
		}
		output, err := os.ReadFile(command.Stdout.Path)
		if err != nil {
			return err
		}
		if strings.ReplaceAll(string(nativeOutput), native.Root, "$CASE") != strings.ReplaceAll(string(output), r.Root, "$CASE") {
			return fmt.Errorf("informational command output differs from native npm")
		}
	}
	state, err := npmProjectState(r, "after")
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(before))
	for path := range before {
		paths = append(paths, path)
	}
	after, err := npmProjectSnapshot(r, "after", paths)
	if err != nil {
		return err
	}
	if _, err := os.Stat(r.Env["SCFW_LOG_FILE"]); err == nil {
		if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := assertCleanup(r, string(stderr)); err != nil {
		return err
	}
	if options.variant == "pre7-install" && r.Spec.Mode == "resolution" {
		if command.ExitCode == 0 || !strings.Contains(string(stderr), "npm before v7.0.0 is not supported") {
			return fmt.Errorf("missing npm resolution minimum-version rejection")
		}
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(previous, state) {
			return fmt.Errorf("minimum-version rejection changed project")
		}
		if _, err := os.Stat(r.Env["SCFW_LOG_FILE"]); !os.IsNotExist(err) {
			return fmt.Errorf("minimum guard produced a policy log: %v", err)
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "REJECT"
		return nil
	}
	if slices.Contains([]string{"global-production", "global-workspace-member", "global-self", "production-no-save", "dev-no-save", "prefix-separate-no-save", "prefix-equals-no-save"}, options.variant) && !reflect.DeepEqual(before, after) {
		return fmt.Errorf("global/no-save install changed the local project")
	}
	blocked := options.block && !production && !(options.variant == "ci" && r.Spec.Mode == "resolution")
	if production && options.block {
		r.Result.Observations["omitted_dev_finding"] = target.Project + "@" + target.Version
	}
	if blocked && command.ExitCode == 0 || !blocked && command.ExitCode != nativeCommand.ExitCode {
		return fmt.Errorf("SCFW exit %d, native %d, required BLOCK=%t", command.ExitCode, nativeCommand.ExitCode, blocked)
	}
	targets := npmProjectTargets(expected, nativeBefore)
	if options.variant == "ci" && r.Spec.Mode == "resolution" {
		targets = nil
		r.Result.Observations["coverage_boundary"] = "resolution npm ci executes uninspected; list finding deliberately does not protect it"
	}
	if err := npmProjectPolicy(r, targets, target, blocked); err != nil {
		return err
	}
	if blocked {
		for _, pkg := range state {
			if pkg.Name == target.Project && pkg.Version == target.Version {
				return fmt.Errorf("blocked exact package is installed at %s", pkg.Path)
			}
		}
		if r.Spec.Mode == "resolution" && (!reflect.DeepEqual(before, after) || !reflect.DeepEqual(previous, state)) {
			return fmt.Errorf("resolution BLOCK changed original manifest/lock/installation")
		}
	} else {
		if !reflect.DeepEqual(expected, state) {
			return fmt.Errorf("installed state differs from native: got %+v; want %+v", state, expected)
		}
		if err := npmProjectArtifacts(r, state, candidates); err != nil {
			return err
		}
	}
	if options.variant == "marker" || options.variant == "final-failure" {
		_, nativeMarker := os.Stat(filepath.Join(native.WorkDir, "final-install.marker"))
		_, marker := os.Stat(filepath.Join(r.WorkDir, "final-install.marker"))
		if nativeMarker != nil || (!blocked && marker != nil) || (blocked && r.Spec.Mode == "resolution" && !os.IsNotExist(marker)) {
			return fmt.Errorf("incorrect final-project marker: native=%v wrapped=%v", nativeMarker, marker)
		}
		r.Result.Observations["marker_scope"] = "postinstall in the original project directory only; no assertion about script execution during resolution"
	}
	if options.variant == "unresolved" {
		nativeStderr, err := os.ReadFile(nativeCommand.Stderr.Path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(nativeStderr), "ETARGET") || !strings.Contains(string(stderr), "ETARGET") {
			return fmt.Errorf("native resolution error diagnostic was not preserved")
		}
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(previous, state) {
			return fmt.Errorf("unresolved install changed the original project")
		}
	}
	return nil
}
func npmProjectTargets(after, before []npmProjectPackage) []npmProjectPackage {
	var targets []npmProjectPackage
	for _, pkg := range after {
		if !pkg.Local && !slices.Contains(before, pkg) {
			targets = append(targets, pkg)
		}
	}
	return targets
}
func npmProjectArtifacts(r *caseRun, state []npmProjectPackage, candidates []candidate) error {
	locks := map[string]npmGraphLock{}
	global := r.Env["npm_config_prefix"] != ""
	for _, pkg := range state {
		if pkg.Local {
			continue
		}
		prefix, _, ok := strings.Cut(pkg.Path, "node_modules/")
		if !ok {
			return fmt.Errorf("installed package has no module path: %s", pkg.Path)
		}
		// Root workspace locks also own unhoisted member entries. Some npm
		// versions instead write a standalone lock for member-directory installs.
		if prefix != "" && !global {
			var rootLock npmGraphLock
			err := readJSON(filepath.Join(r.WorkDir, "package-lock.json"), &rootLock)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if rootLock.Packages[pkg.Path].Version != "" {
				prefix = ""
			}
		}
		lock, exists := locks[prefix]
		if !exists && !global {
			path := filepath.Join(r.WorkDir, filepath.FromSlash(prefix), "package-lock.json")
			if err := readJSON(path, &lock); err != nil {
				return err
			}
			locks[prefix] = lock
			if err := r.Keep("installed-lock-"+filepath.Base(r.Root)+"-"+prefix, path); err != nil {
				return err
			}
		}
		found := false
		for _, c := range candidates {
			if pkg.Name != c.Project || pkg.Version != c.Version {
				continue
			}
			found = true
			if global {
				downloaded := false
				for _, command := range r.Result.Commands {
					directory := r.WorkDir
					if strings.Contains(r.Spec.Variant, "-global-workspace-member-") {
						directory = filepath.Join(directory, "packages/member")
					}
					if command.Cwd != directory {
						continue
					}
					log, err := os.ReadFile(command.Stderr.Path)
					if err != nil {
						return err
					}
					downloaded = downloaded || bytes.Contains(log, []byte(c.Artifacts[0].URL))
				}
				if !downloaded {
					return fmt.Errorf("missing public global artifact download for %s@%s", c.Project, c.Version)
				}
				continue
			}
			// npm6 has lockfile v1; path-specific artifact checks start at npm7.
			if strings.HasPrefix(r.Cell.ManagerVersion, "6.") {
				continue
			}
			entry := lock.Packages[strings.TrimPrefix(pkg.Path, prefix)]
			if entry.Version != c.Version || entry.Resolved != c.Artifacts[0].URL || entry.Integrity != c.Artifacts[0].Integrity {
				return fmt.Errorf("native/installed artifact mismatch at %s", pkg.Path)
			}
		}
		if !found {
			return fmt.Errorf("native selected an undiscovered package: %+v", pkg)
		}
	}
	if global {
		r.Result.Observations["global_artifact_evidence"] = "native installed identity and public tarball URL in client download log; npm global installs have no project lock"
	}
	return nil
}
func npmProjectPolicy(r *caseRun, targets []npmProjectPackage, target candidate, blocked bool) error {
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	unresolvedResolution := r.Spec.Mode == "resolution" && r.Spec.Variant == "resolution-unresolved-allow" && r.Result.SCFWExit > 0
	if len(targets) == 0 && !blocked && (r.Spec.Mode == "proxy" || unresolvedResolution) && os.IsNotExist(err) {
		r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "ALLOW"
		if unresolvedResolution {
			r.Result.ResolvedAction = "REJECT"
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	observed := map[string]bool{}
	for _, record := range records {
		if record.Manager != "npm" || record.Executable != r.Cell.Executable {
			return fmt.Errorf("unexpected report identity")
		}
		for _, pkg := range record.Packages {
			if strings.HasPrefix(pkg.Name, "scfw-e2e-") {
				continue
			}
			if !slices.ContainsFunc(targets, func(want npmProjectPackage) bool { return pkg.Name == want.Name && pkg.Version == want.Version }) {
				return fmt.Errorf("evaluated an unselected version: %s@%s", pkg.Name, pkg.Version)
			}
			observed[pkg.Name+"@"+pkg.Version] = true
			if !blocked && pkg.Outcome != "ALLOW" {
				return fmt.Errorf("unexpected package outcome %s", pkg.Outcome)
			}
		}
	}
	if blocked {
		for _, record := range records {
			for _, pkg := range record.Packages {
				if pkg.Name == target.Project && pkg.Version == target.Version && pkg.Outcome == "BLOCK" {
					if err := assertPolicy([]policyRecord{record}, target, "npm", r.Cell.Executable, "BLOCK"); err != nil {
						return err
					}
					r.Result.PolicyOutcome, r.Result.ResolvedAction = "BLOCK", "BLOCK"
					return nil
				}
			}
		}
		return fmt.Errorf("missing exact-version required BLOCK")
	}
	for _, pkg := range targets {
		if !observed[pkg.Name+"@"+pkg.Version] {
			return fmt.Errorf("selected package was not evaluated: %s@%s", pkg.Name, pkg.Version)
		}
	}
	for _, record := range records {
		if record.Outcome != "ALLOW" {
			return fmt.Errorf("native failure/uninspected command misreported as policy %s", record.Outcome)
		}
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = "ALLOW", "ALLOW"
	return nil
}
func TestHarnessNPMProjectTargets(t *testing.T) {
	old := npmProjectPackage{Path: "node_modules/example", Name: "example", Version: "1"}
	newer := old
	newer.Version = "2"
	duplicate := old
	duplicate.Path = "node_modules/other/node_modules/example"
	local := npmProjectPackage{Path: "node_modules/local", Name: "local", Version: "1", Local: true}
	if got := npmProjectTargets([]npmProjectPackage{old, newer, duplicate, local}, []npmProjectPackage{old}); !reflect.DeepEqual(got, []npmProjectPackage{newer, duplicate}) {
		t.Fatalf("incorrect changed/duplicate/local selection: %+v", got)
	}
}

func TestHarnessNPMProjectMissingPolicy(t *testing.T) {
	for _, c := range []struct {
		name, mode, variant, logState, outcome, action string
		exit                                           int
		targets, blocked, wantError                    bool
	}{
		{name: "failed-resolution", mode: "resolution", variant: "resolution-unresolved-allow", exit: 1, outcome: "NOT_OBSERVED", action: "REJECT"},
		{name: "successful-resolution", mode: "resolution", variant: "resolution-unresolved-allow", wantError: true},
		{name: "failed-launch", mode: "resolution", variant: "resolution-unresolved-allow", exit: -1, wantError: true},
		{name: "ordinary-resolution", mode: "resolution", variant: "resolution-manifest-no-lock-allow", wantError: true},
		{name: "final-command-failure", mode: "resolution", variant: "resolution-final-failure-allow", exit: 1, wantError: true},
		{name: "selected-target", mode: "resolution", variant: "resolution-unresolved-allow", exit: 1, targets: true, wantError: true},
		{name: "required-block", mode: "resolution", variant: "resolution-unresolved-allow", exit: 1, blocked: true, wantError: true},
		{name: "empty-log", mode: "resolution", variant: "resolution-unresolved-allow", exit: 1, logState: "empty", wantError: true},
		{name: "unreadable-log", mode: "resolution", variant: "resolution-unresolved-allow", exit: 1, logState: "directory", wantError: true},
		{name: "proxy-no-targets", mode: "proxy", variant: "proxy-unresolved-allow", exit: 1, outcome: "NOT_OBSERVED", action: "ALLOW"},
		{name: "proxy-selected-target", mode: "proxy", variant: "proxy-manifest-no-lock-allow", targets: true, wantError: true},
		{name: "proxy-required-block", mode: "proxy", variant: "proxy-manifest-no-lock-block", blocked: true, wantError: true},
		{name: "ordinary-policy-report", mode: "resolution", variant: "resolution-manifest-no-lock-allow", targets: true, logState: "allow", outcome: "ALLOW", action: "ALLOW"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.jsonl")
			target := candidate{Project: "selected", Version: "1"}
			r := &caseRun{Cell: cell{Executable: "/selected/npm"}, Spec: scenario{Mode: c.mode, Variant: c.variant}, Env: map[string]string{"SCFW_LOG_FILE": path}, Result: &result{SCFWExit: c.exit, Evidence: map[string]fileEvidence{}}}
			switch c.logState {
			case "empty":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "allow":
				record := policyRecord{Manager: "npm", Executable: r.Cell.Executable, Outcome: "ALLOW", Packages: []policyPackage{{Name: target.Project, Version: target.Version, Outcome: "ALLOW"}}}
				if err := writeJSON(path, record); err != nil {
					t.Fatal(err)
				}
			}
			var targets []npmProjectPackage
			if c.targets {
				targets = []npmProjectPackage{{Name: target.Project, Version: target.Version}}
			}
			err := npmProjectPolicy(r, targets, target, c.blocked)
			if (err != nil) != c.wantError {
				t.Fatalf("policy error=%v, wantError=%t", err, c.wantError)
			}
			if err == nil && (r.Result.PolicyOutcome != c.outcome || r.Result.ResolvedAction != c.action) {
				t.Fatalf("policy=%s action=%s, want %s/%s", r.Result.PolicyOutcome, r.Result.ResolvedAction, c.outcome, c.action)
			}
		})
	}
}
