// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// pnpm 11 and 12 verify that node_modules is in sync before a script and,
// unless verifyDepsBeforeRun says otherwise, install first: a script whose
// dependencies pnpm considers out of date downloads them before the script
// runs. SCFW runs such a script through the proxy, so the install is
// evaluated; everything it cannot decide is proxied too, because that keeps
// ordinary scripts running while never leaving an install unevaluated. A
// failed gate install only warns in pnpm, so the script still runs.

// installsBeforeScript reports whether pnpm major may install dependencies
// before running a script in dir, from the environment, the command line, the
// workspace's pnpm-workspace.yaml, and the global config.yaml. It reads only
// files: nothing about pnpm runs here.
func installsBeforeScript(major int, parsed parsedCommand, dir string, environ []string) bool {
	if major < 11 {
		return false
	}
	env := nodeproxy.LookupEnvironment(environ)
	pnpmEnv := pnpmEnvironmentConfig(environ, major)

	root := configRoot(dir)
	if !regularFile(filepath.Join(root, "package.json")) && !regularFile(filepath.Join(root, "pnpm-workspace.yaml")) {
		// pnpm skips the gate without a root project.
		return false
	}
	workspace, err := readWorkspaceSettings(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return true
	}
	global, err := readWorkspaceSettings(filepath.Join(configDir(env), "config.yaml"))
	if err != nil {
		return true
	}

	// pnpm resolves verifyDepsBeforeRun from the pnpm_config_* variable first
	// (it sets one itself in every script it spawns), then the command line,
	// the workspace's file, and the global one, and defaults to installing.
	action := nodeproxy.LastValue(pnpmEnv["verify-deps-before-run"])
	if action == "" {
		action = nodeproxy.LastValue(parsed.network["verify-deps-before-run"])
	}
	if action == "" {
		action, _ = layers{workspace, global}.scalar("verify-deps-before-run")
	}
	if action == "" {
		action = "install" // pnpm's default
	}
	switch action {
	case "false", "warn", "error", "true":
		// pnpm checks, warns, or fails, but never installs.
		return false
	case "install", "prompt":
		// prompt installs too, but asks first; SCFW cannot answer, so it
		// treats it like install.
	default:
		return true
	}

	// Layouts the checks below cannot reproduce: a separate lockfile or
	// modules directory, per-project lockfiles, or git-branch lockfiles put
	// the state somewhere else or change what current means.
	for _, layer := range []nodeproxy.Config{parsed.network, pnpmEnv, workspace, global} {
		for key, values := range layer {
			switch key {
			case "lockfile-dir", "modules-dir":
				if nodeproxy.LastValue(values) != "" {
					return true
				}
			case "shared-workspace-lockfile":
				if nodeproxy.LastValue(values) == "false" {
					return true
				}
			case "git-branch-lockfile", "merge-git-branch-lockfiles":
				if nodeproxy.LastValue(values) == "true" {
					return true
				}
			}
		}
	}
	return dependenciesStale(root, workspace, env)
}

// dependenciesStale reports whether the workspace state pnpm's gate reads
// proves the root current: a missing or partial state, a changed file, or a
// project structure that no longer matches all mean pnpm would install.
func dependenciesStale(root string, workspace nodeproxy.Config, env map[string]string) bool {
	data, err := nodeproxy.ReadConfigFile(filepath.Join(root, "node_modules", ".pnpm-workspace-state-v1.json"))
	var state struct {
		LastValidatedTimestamp int64 `json:"lastValidatedTimestamp"`
		Projects               map[string]struct {
			HasModulesDir bool `json:"hasModulesDir"`
		} `json:"projects"`
		Pnpmfiles       []string `json:"pnpmfiles"`
		FilteredInstall bool     `json:"filteredInstall"`
	}
	parsed := err == nil && json.Unmarshal(data, &state) == nil
	if !parsed || state.LastValidatedTimestamp == 0 || state.FilteredInstall {
		// Nothing was installed here. pnpm still runs the script when the
		// projects it would cover declare no dependency and no pnpmfile
		// hooks run; anything else means an install.
		projects, ok := currentProjects(root, workspace)
		if !ok {
			return true
		}
		for _, pnpmfile := range []string{".pnpmfile.cjs", ".pnpmfile.mjs"} {
			if regularFile(filepath.Join(root, pnpmfile)) {
				return true
			}
		}
		for project := range projects {
			manifest, err := readManifest(filepath.Join(project, "package.json"))
			if err != nil || manifest.declaresDependencies() || manifest.Pnpm != nil {
				return true
			}
		}
		return false
	}
	// pnpm keys projects by absolute path; the directory may carry a symlink.
	if _, found := state.Projects[root]; !found {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return true
		}
		if _, found = state.Projects[resolved]; !found {
			return true
		}
	}

	projects := recordedProjects(state.Projects)
	if regularFile(filepath.Join(root, "pnpm-workspace.yaml")) {
		found, ok := workspaceProjects(root, workspace["packages"])
		if !ok || !sameProjects(found, projects) {
			return true
		}
	}

	// Every input pnpm compares, newest first against the install: the
	// manifests, the lockfile, the workspace file, the pnpmfiles and patches,
	// and the global, root, and user configuration.
	compared := []string{
		filepath.Join(root, "pnpm-lock.yaml"),
		filepath.Join(root, "pnpm-workspace.yaml"),
		filepath.Join(root, ".npmrc"),
		filepath.Join(configDir(env), "config.yaml"),
		filepath.Join(env["HOME"], ".npmrc"),
		filepath.Join(root, ".pnpmfile.cjs"), filepath.Join(root, ".pnpmfile.mjs"),
	}
	compared = append(compared, state.Pnpmfiles...)
	compared = append(compared, patchFiles(root)...)
	declares := map[string]bool{}
	for project := range projects {
		manifest, err := readManifest(filepath.Join(project, "package.json"))
		if err != nil {
			return true
		}
		compared = append(compared, filepath.Join(project, "package.json"))
		declares[project] = manifest.declaresDependencies()
		if manifest.Pnpm != nil {
			return true // the ignored "pnpm" field makes an install refuse
		}
	}
	for _, path := range compared {
		if modifiedAfter(path, state.LastValidatedTimestamp) {
			return true
		}
	}

	// Dependencies were required, so an install must have left its lockfile
	// and every declaring project a modules directory.
	none := true
	for project, declaresDeps := range declares {
		if declaresDeps {
			none = false
			if _, err := os.Stat(filepath.Join(project, "node_modules")); err != nil {
				return true
			}
		}
	}
	if none {
		return false
	}
	for _, path := range []string{
		filepath.Join(root, "pnpm-lock.yaml"),
		filepath.Join(root, "node_modules", ".pnpm", "lock.yaml"),
	} {
		if !regularFile(path) {
			return true
		}
	}
	return false
}

func recordedProjects(projects map[string]struct {
	HasModulesDir bool `json:"hasModulesDir"`
}) map[string]bool {
	recorded := make(map[string]bool, len(projects))
	for project := range projects {
		recorded[project] = true
	}
	return recorded
}

// sameProjects compares two project sets by their physical paths, because
// pnpm keys its state by absolute paths that may carry a symlink.
func sameProjects(found, recorded map[string]bool) bool {
	canonical := func(paths map[string]bool) map[string]bool {
		set := make(map[string]bool, len(paths))
		for path := range paths {
			if resolved, err := filepath.EvalSymlinks(path); err == nil {
				path = resolved
			}
			set[filepath.Clean(path)] = true
		}
		return set
	}
	found, recorded = canonical(found), canonical(recorded)
	if len(found) != len(recorded) {
		return false
	}
	for project := range found {
		if !recorded[project] {
			return false
		}
	}
	return true
}

// currentProjects lists the projects a non-recursive install covers: the
// root, and the workspace members its packages patterns select.
func currentProjects(root string, workspace nodeproxy.Config) (map[string]bool, bool) {
	projects := map[string]bool{}
	if regularFile(filepath.Join(root, "package.json")) {
		projects[root] = true
	}
	if regularFile(filepath.Join(root, "pnpm-workspace.yaml")) {
		found, ok := workspaceProjects(root, workspace["packages"])
		if !ok {
			return nil, false
		}
		for project := range found {
			projects[project] = true
		}
	}
	return projects, true
}

// workspaceProjects lists the projects the workspace's packages patterns
// select, mirroring pnpm's `**`, `*`, `?`, and `[...]` globs while
// skipping node_modules. Patterns using features the matcher does
// not reproduce, such as braces, extglobs, and negation, cannot be decided.
func workspaceProjects(root string, patterns []string) (map[string]bool, bool) {
	projects := map[string]bool{root: true}
	if !regularFile(filepath.Join(root, "package.json")) {
		delete(projects, root)
	}
	for _, pattern := range patterns {
		if pattern == "" || strings.ContainsAny(pattern, "{}!()") {
			return nil, false
		}
		matches, ok := globProjects(root, strings.Split(pattern, "/"))
		if !ok {
			return nil, false
		}
		for match := range matches {
			projects[match] = true
		}
	}
	return projects, true
}

// globProjects walks dir for the projects a pattern's segments select. Every
// segment but `**` matches within one directory, and a segment that
// is not a manifest directory ends the walk there.
func globProjects(dir string, segments []string) (map[string]bool, bool) {
	projects := map[string]bool{}
	if len(segments) == 0 {
		return projects, true
	}
	segment, rest := segments[0], segments[1:]
	if segment == "**" {
		if len(rest) == 0 {
			return nil, false // a trailing ** selects every project
		}
		if found, ok := globProjects(dir, rest); ok {
			for project := range found {
				projects[project] = true
			}
		} else {
			return nil, false
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return projects, true
		}
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "node_modules" {
				if found, ok := globProjects(filepath.Join(dir, entry.Name()), segments); ok {
					for project := range found {
						projects[project] = true
					}
				} else {
					return nil, false
				}
			}
		}
		return projects, true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return projects, true
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "node_modules" || !globSegment(segment, entry.Name()) {
			continue
		}
		match := filepath.Join(dir, entry.Name())
		if len(rest) == 0 {
			if regularFile(filepath.Join(match, "package.json")) {
				projects[match] = true
			}
			continue
		}
		found, ok := globProjects(match, rest)
		if !ok {
			return nil, false
		}
		for project := range found {
			projects[project] = true
		}
	}
	return projects, true
}

// globSegment matches one pattern segment against a name, with *, ?, and a
// character class.
func globSegment(pattern, name string) bool {
	return globMatch([]rune(pattern), []rune(name))
}

func globMatch(pattern, name []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			for index := range name {
				if globMatch(pattern, name[index:]) {
					return true
				}
			}
			return false
		case '?':
			if len(name) == 0 {
				return false
			}
			pattern, name = pattern[1:], name[1:]
		case '[':
			closing := -1
			for index, char := range pattern {
				if index > 0 && char == ']' {
					closing = index
					break
				}
			}
			if closing < 1 || len(name) == 0 {
				return false
			}
			if !classMatch(pattern[1:closing], name[0]) {
				return false
			}
			pattern, name = pattern[closing+1:], name[1:]
		default:
			if len(name) == 0 || name[0] != pattern[0] {
				return false
			}
			pattern, name = pattern[1:], name[1:]
		}
	}
	return len(name) == 0
}

func classMatch(class []rune, char rune) bool {
	negated := len(class) > 0 && class[0] == '^'
	if negated {
		class = class[1:]
	}
	for index := 0; index < len(class); index++ {
		if index+2 < len(class) && class[index+1] == '-' {
			if class[index] <= char && char <= class[index+2] {
				return !negated
			}
			index += 2
			continue
		}
		if class[index] == char {
			return !negated
		}
	}
	return negated
}

// modifiedAfter reports whether path changed after the timestamp pnpm's
// install recorded, comparing whole milliseconds like pnpm's gate.
func modifiedAfter(path string, timestamp int64) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.ModTime().UnixMilli() > timestamp
}

type projectManifest struct {
	Dependencies         map[string]any `json:"dependencies"`
	DevDependencies      map[string]any `json:"devDependencies"`
	OptionalDependencies map[string]any `json:"optionalDependencies"`
	PeerDependencies     map[string]any `json:"peerDependencies"`
	Pnpm                 map[string]any `json:"pnpm"`
}

// declaresDependencies counts peers too, because pnpm's default
// auto-install-peers installs them.
func (manifest *projectManifest) declaresDependencies() bool {
	return len(manifest.Dependencies)+len(manifest.DevDependencies)+len(manifest.OptionalDependencies)+
		len(manifest.PeerDependencies) > 0
}

func readManifest(path string) (*projectManifest, error) {
	data, err := nodeproxy.ReadConfigFile(path)
	if err != nil {
		return nil, err
	}
	var manifest projectManifest
	if json.Unmarshal(data, &manifest) != nil {
		return nil, errors.New("could not read manifest")
	}
	return &manifest, nil
}

// patchFiles lists the files the workspace's patchedDependencies name, which
// an install records and compares.
func patchFiles(root string) []string {
	data, err := nodeproxy.ReadConfigFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return nil
	}
	var workspace struct {
		PatchedDependencies map[string]yaml.Node `yaml:"patchedDependencies"`
	}
	if yaml.Unmarshal(data, &workspace) != nil {
		return nil // a file SCFW cannot parse cannot be decided
	}
	var paths []string
	for _, patch := range workspace.PatchedDependencies {
		path := ""
		switch patch.Kind {
		case yaml.ScalarNode:
			path = patch.Value
		case yaml.MappingNode:
			for index := 0; index+1 < len(patch.Content); index += 2 {
				if patch.Content[index].Value == "path" {
					path = patch.Content[index+1].Value
				}
			}
		}
		if path == "" {
			return nil
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		paths = append(paths, path)
	}
	return paths
}
