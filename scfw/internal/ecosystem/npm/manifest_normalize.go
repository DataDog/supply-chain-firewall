// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"path"
	"sort"
	"strings"
)

// comparisonManifest selects the fields whose differences are enforced. Unknown
// top-level fields and descriptive metadata do not participate in comparison.
// Identity and distribution integrity also receive independent checks.
func comparisonManifest(m map[string]any) map[string]any {
	selected := make(map[string]any)
	for _, key := range []string{
		"name", "version", "scripts",
		"dependencies", "devDependencies", "optionalDependencies",
		"peerDependencies", "peerDependenciesMeta", "bundleDependencies", "bundledDependencies",
		"bin", "main", "exports", "imports", "type", "engines", "libc", "files",
		"gypfile", "hasInstallScript", "_hasShrinkwrap",
	} {
		if value, present := m[key]; present {
			selected[key] = value
		}
	}
	if value, present := m["directories"]; present {
		if directories, ok := value.(map[string]any); ok {
			if bin, present := directories["bin"]; present {
				selected["directories"] = map[string]any{"bin": bin}
			}
		} else {
			selected["directories"] = value
		}
	}
	return selected
}

// Normalizations follow npm/cli v11.6.2 @npmcli/package-json normalize.js.
// Selected objects, including dependencies and scripts, are compared recursively.
func normalizeManifest(m map[string]any, facts ArchiveFacts) {
	if bin, ok := m["bin"].(string); ok {
		name, _ := m["name"].(string)
		m["bin"] = map[string]any{path.Base(name): strings.TrimPrefix(bin, "./")}
	}
	if bin, ok := m["bin"].(map[string]any); ok {
		for k, v := range bin {
			if s, ok := v.(string); ok {
				bin[k] = strings.TrimPrefix(s, "./")
			}
		}
	}
	if v, ok := m["bundleDependencies"]; ok {
		if _, exists := m["bundledDependencies"]; !exists {
			m["bundledDependencies"] = v
			delete(m, "bundleDependencies")
		}
	}
	if v, ok := m["bundledDependencies"].(bool); ok {
		if v {
			names := map[string]bool{}
			for _, k := range []string{"dependencies"} {
				if deps, ok := m[k].(map[string]any); ok {
					for n := range deps {
						names[n] = true
					}
				}
			}
			a := []any{}
			for n := range names {
				a = append(a, n)
			}
			m["bundledDependencies"] = a
		} else {
			m["bundledDependencies"] = []any{}
		}
	}
	if object, ok := m["bundledDependencies"].(map[string]any); ok {
		a := []any{}
		for k := range object {
			a = append(a, k)
		}
		m["bundledDependencies"] = a
	}
	if a, ok := m["bundledDependencies"].([]any); ok {
		valid := true
		for _, v := range a {
			if _, ok := v.(string); !ok {
				valid = false
			}
		}
		if valid {
			sort.Slice(a, func(i, j int) bool { return a[i].(string) < a[j].(string) })
		}
	}
	if optional, ok := m["optionalDependencies"].(map[string]any); ok {
		if deps, ok := m["dependencies"].(map[string]any); ok {
			for n := range optional {
				delete(deps, n)
			}
			if len(deps) == 0 {
				delete(m, "dependencies")
			}
		}
	}
	// Defaults are reconstructed identically on both sides from archive facts.
	// An explicit script, including an empty string, is always preserved.
	scripts, _ := m["scripts"].(map[string]any)
	if facts.BindingGyp && m["gypfile"] != false {
		_, install := scripts["install"]
		_, preinstall := scripts["preinstall"]
		if !install && !preinstall {
			if scripts == nil {
				scripts = map[string]any{}
				m["scripts"] = scripts
			}
			scripts["install"] = "node-gyp rebuild"
		}
	}
	// Derived indicators are replaced with actual facts only when absent. Values
	// supplied by the registry must still compare to those facts.
	has := false
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if v, ok := scripts[k].(string); ok && v != "" {
			has = true
		}
	}
	if _, ok := m["hasInstallScript"]; !ok {
		m["hasInstallScript"] = has
	}
	if _, ok := m["_hasShrinkwrap"]; !ok {
		m["_hasShrinkwrap"] = facts.Shrinkwrap
	}
	if _, ok := m["gypfile"]; !ok && facts.BindingGyp {
		m["gypfile"] = true
	}
}
