// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// classicTarget follows `yarn workspace <name> <command>`, which runs
// <command> in a second Yarn started inside the workspace, to the process that
// runs the command. moved reports whether it left dir.
func classicTarget(dir string, command []string, env map[string]string) (process classicProcess, moved bool, err error) {
	process, err = newClassicProcess(dir, command, env)
	for err == nil && process.cmd.workspace != "" {
		var workspace string
		if workspace, err = classicWorkspace(process); err != nil || workspace == "" {
			break
		}
		process, err = newClassicProcess(workspace, process.cmd.inner, env)
		moved = true
	}
	return process, moved, err
}

// classicWorkspace returns the directory of the workspace process names, as
// Yarn Classic resolves it. It returns "" where Yarn fails, which leaves the
// command for Yarn to report, and an error where SCFW cannot tell.
func classicWorkspace(process classicProcess) (string, error) {
	root, patterns, unsupported := classicWorkspaceRoot(process.project)
	if root == "" {
		if unsupported {
			return "", unsupportedWorkspacePattern(process.cmd.workspace)
		}
		return "", nil
	}
	members, unsupported, err := classicWorkspaces(root, patterns)
	if err != nil || members == nil {
		return "", err
	}
	if directory, found := members[process.cmd.workspace]; found {
		return directory, nil
	}
	if unsupported {
		return "", unsupportedWorkspacePattern(process.cmd.workspace)
	}
	return "", nil
}

// classicWorkspaceRoot mirrors findWorkspaceRoot: the nearest manifest at or
// above project whose workspaces declare packages is the root, and project
// must be that root or match its patterns, where "!" patterns exclude. It
// returns "" where Yarn has no root or refuses it: a malformed manifest, or
// packages without "private".
func classicWorkspaceRoot(project string) (root string, patterns []string, unsupported bool) {
	for current := project; ; current = filepath.Dir(current) {
		manifest, found, err := readWorkspaceManifest(current)
		if found && err != nil {
			return "", nil, false
		}
		if patterns, declared := workspacePatterns(manifest.Workspaces); found && declared {
			relative, err := filepath.Rel(current, project)
			if err != nil {
				return "", nil, false
			}
			member, unsupported := relative == ".", false
			if !member {
				member, unsupported = classicMember(filepath.ToSlash(relative), patterns)
			}
			if !member || len(patterns) > 0 && !truthy(manifest.Private) {
				return "", nil, unsupported
			}
			return current, patterns, false
		}
		if filepath.Dir(current) == current {
			return "", nil, false
		}
	}
}

// classicMember matches a relative path against workspace patterns as
// micromatch does for a list: braces expand, "!" patterns exclude, and names
// compare case-sensitively.
func classicMember(relative string, patterns []string) (member, unsupported bool) {
	path := patternSegments(relative)
	included, excluded := false, false
	for _, pattern := range patterns {
		pattern, negated := strings.CutPrefix(pattern, "!")
		for _, expanded := range nodeproxy.ExpandBraces(pattern) {
			unsupported = unsupported || unsupportedGlob(expanded)
			if matchPath(patternSegments(expanded), path) {
				excluded, included = excluded || negated, included || !negated
			}
		}
	}
	return included && !excluded, unsupported
}

// classicWorkspaces mirrors resolveWorkspaces: the directories the root's
// patterns select, where a leading "!" is literal, by the name in their
// manifest. A member needs a name and a version. members is nil where Yarn
// fails: a malformed manifest or a duplicate name.
func classicWorkspaces(root string, patterns []string) (members map[string]string, unsupported bool, err error) {
	glob := newWorkspaceGlob(false)
	members = map[string]string{}
	seen := map[string]bool{}
	for _, pattern := range patterns {
		for _, expanded := range nodeproxy.ExpandBraces(pattern) {
			unsupported = unsupported || unsupportedGlob(expanded)
			matches, err := glob.directories(root, expanded)
			if err != nil {
				return nil, false, err
			}
			for _, match := range matches {
				if seen[match] {
					continue
				}
				seen[match] = true
				// Yarn joins even an absolute match to the root.
				location := filepath.Join(root, filepath.FromSlash(match))
				manifest, found, err := readWorkspaceManifest(location)
				if err := glob.charge(1); err != nil {
					return nil, false, err
				}
				if found && err != nil {
					return nil, false, nil
				}
				name, _ := manifest.Name.(string)
				if !found || name == "" || !truthy(manifest.Version) {
					continue
				}
				if _, duplicate := members[name]; duplicate {
					return nil, false, nil
				}
				members[name] = location
			}
		}
	}
	return members, unsupported, nil
}
