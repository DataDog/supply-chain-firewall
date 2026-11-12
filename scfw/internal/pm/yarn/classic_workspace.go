// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"encoding/json"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// classicWorkspace resolves `yarn workspace <name> <command...>`. Yarn runs
// <command...> in a second Yarn process started inside the workspace, which
// receives none of the outer process's options. It returns the workspace
// directory and the arguments of <command...>; an unknown name is left for
// Yarn to report.
func classicWorkspace(start string, cmd yarnCommand, command []string) (directory string, rest []string, found bool) {
	if cmd.name != "workspace" || len(cmd.args) < 2 {
		return "", nil, false
	}
	directory, found = workspaceDirectories(start)[cmd.args[0]]
	return directory, command[cmd.index+2:], found
}

// workspaceDirectories maps workspace names to their directories, using the
// nearest package.json above start that declares workspaces. Patterns support
// the * and ** wildcards; node_modules and .git are never searched.
func workspaceDirectories(start string) map[string]string {
	directories := map[string]string{}
	for root := start; ; root = filepath.Dir(root) {
		var manifest struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		data, err := nodeproxy.ReadConfigFile(filepath.Join(root, "package.json"))
		if err == nil && json.Unmarshal(data, &manifest) == nil && len(manifest.Workspaces) > 0 {
			var patterns []string
			var object struct {
				Packages []string `json:"packages"`
			}
			if json.Unmarshal(manifest.Workspaces, &patterns) != nil && json.Unmarshal(manifest.Workspaces, &object) == nil {
				patterns = object.Packages
			}
			collectWorkspaces(root, patterns, directories)
			return directories
		}
		if filepath.Dir(root) == root {
			return directories
		}
	}
}

func collectWorkspaces(root string, patterns []string, directories map[string]string) {
	_ = filepath.WalkDir(root, func(directory string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		if entry.Name() == "node_modules" || entry.Name() == ".git" {
			return filepath.SkipDir
		}
		relative, err := filepath.Rel(root, directory)
		if err != nil || relative == "." {
			return nil
		}
		for _, pattern := range patterns {
			if !matchSegments(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(filepath.ToSlash(relative), "/")) {
				continue
			}
			var manifest struct {
				Name string `json:"name"`
			}
			data, err := nodeproxy.ReadConfigFile(filepath.Join(directory, "package.json"))
			if err == nil && json.Unmarshal(data, &manifest) == nil && manifest.Name != "" {
				directories[manifest.Name] = directory
			}
			break
		}
		return nil
	})
}

// matchSegments matches a workspace pattern against a relative path, one path
// segment at a time; "**" matches any number of segments.
func matchSegments(pattern, parts []string) bool {
	if len(pattern) == 0 {
		return len(parts) == 0
	}
	if pattern[0] == "**" {
		for skipped := 0; skipped <= len(parts); skipped++ {
			if matchSegments(pattern[1:], parts[skipped:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], parts[0])
	return err == nil && matched && matchSegments(pattern[1:], parts[1:])
}
