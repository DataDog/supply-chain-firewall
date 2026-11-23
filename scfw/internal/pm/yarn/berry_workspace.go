// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// berryProject mirrors Yarn 4's findProjectCwd: the nearest directory at or
// above start with a yarn.lock, else the topmost one with a package.json.
func berryProject(start string) string {
	project := ""
	for current := start; ; current = filepath.Dir(current) {
		if _, err := os.Stat(filepath.Join(current, "yarn.lock")); err == nil {
			return current
		}
		if _, err := os.Stat(filepath.Join(current, "package.json")); err == nil {
			project = current
		}
		if filepath.Dir(current) == current {
			return project
		}
	}
}

// berryWorkspace returns the directory of the workspace Yarn 4 names name in
// the project of dir. It returns "" where Yarn fails, which leaves the
// command for Yarn to report, and an error where SCFW cannot tell.
func berryWorkspace(dir, name string) (string, error) {
	names, _, unsupported, err := berryWorkspaces(berryProject(dir))
	if err != nil || names == nil {
		return "", err
	}
	if workspace, found := names[name]; found {
		return workspace, nil
	}
	if unsupported {
		return "", unsupportedWorkspacePattern(name)
	}
	return "", nil
}

// berryWorkspaces lists a Yarn 4 project's workspaces, each workspace's own
// patterns adding nested ones: directories holds them all and names the named
// ones. Patterns starting with "!" exclude matches; unsupported also reports
// a "**" that reached a symlinked directory. names is nil where Yarn
// fails to load the project: a missing or malformed manifest, or a duplicate
// name.
func berryWorkspaces(project string) (names map[string]string, directories []string, unsupported bool, err error) {
	if project == "" {
		return nil, nil, false, nil
	}
	glob := newWorkspaceGlob(true)
	names = map[string]string{}
	seen := map[string]bool{}
	for queue := []string{project}; len(queue) > 0; queue = queue[1:] {
		cwd := queue[0]
		if seen[cwd] {
			continue
		}
		seen[cwd] = true
		manifest, found, err := readWorkspaceManifest(cwd, "package.json")
		if err := glob.charge(1); err != nil {
			return nil, nil, false, err
		}
		if !found || err != nil {
			return nil, nil, false, nil
		}
		directories = append(directories, cwd)
		if name, _ := manifest.Name.(string); name != "" {
			if _, duplicate := names[name]; duplicate {
				return nil, nil, false, nil
			}
			names[name] = cwd
		}
		patterns, _ := workspacePatterns(manifest.Workspaces)
		var excluded [][]string
		var candidates []string
		for _, pattern := range patterns {
			pattern, negated := strings.CutPrefix(pattern, "!")
			for _, expanded := range nodeproxy.ExpandBraces(pattern) {
				unsupported = unsupported || unsupportedGlob(expanded)
				if negated {
					excluded = append(excluded, patternSegments(expanded))
					continue
				}
				matches, err := glob.directories(cwd, expanded)
				if err != nil {
					return nil, nil, false, err
				}
				candidates = append(candidates, matches...)
			}
		}
		slices.Sort(candidates)
	candidates:
		for _, match := range candidates {
			for _, pattern := range excluded {
				matched, err := glob.matchPath(pattern, patternSegments(match))
				if err != nil {
					return nil, nil, false, err
				}
				if matched {
					continue candidates
				}
			}
			location := glob.location(cwd, match)
			_, err := os.Stat(filepath.Join(location, "package.json"))
			if err := glob.charge(1); err != nil {
				return nil, nil, false, err
			}
			if err == nil {
				queue = append(queue, location)
			}
		}
	}
	return names, directories, unsupported || glob.incomplete, nil
}
