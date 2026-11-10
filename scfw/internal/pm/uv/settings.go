// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Read configuration without invoking uv or changing its files. Only routing,
// TLS and registry discovery consume these values; uv owns all other settings.
func (uv UV) settings(command []string) (map[string]any, error) {
	options := uv.parseOptions(command)
	working, err := uv.workingDirectory(command)
	if err != nil {
		return nil, err
	}
	script, err := options.scriptPath(working)
	if err != nil {
		return nil, err
	}
	inline, err := scriptSettings(script)
	if err != nil {
		return nil, err
	}
	settings, err := uv.filesystemSettings(command, options, working)
	if err != nil {
		return nil, err
	}
	mergeSettings(settings, inline)
	return settings, nil
}

func (uv UV) filesystemSettings(command []string, options commandOptions, working string) (map[string]any, error) {
	if path := options.value("config-file", "UV_CONFIG_FILE"); path != "" {
		return readSettings(resolvePath(working, path), false)
	}
	if enabled(options.value("no-config", "UV_NO_CONFIG")) {
		return map[string]any{}, nil
	}
	settings := map[string]any{}
	var err error
	if !enabled(os.Getenv("UV_NO_SYSTEM_CONFIG")) {
		directories := os.Getenv("XDG_CONFIG_DIRS")
		if directories == "" {
			directories = "/etc/xdg"
		}
		for _, directory := range append(filepath.SplitList(directories), "/etc") {
			path := filepath.Join(directory, "uv", "uv.toml")
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				settings, err = readSettings(path, false)
				if err != nil {
					return nil, err
				}
				break
			}
		}
	}
	userDirectory := os.Getenv("XDG_CONFIG_HOME")
	if userDirectory == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		userDirectory = filepath.Join(home, ".config")
	}
	user, err := readSettings(filepath.Join(userDirectory, "uv", "uv.toml"), true)
	if err != nil {
		return nil, err
	}
	mergeSettings(settings, user)
	if options.command == "tool" {
		return settings, nil
	}
	project, err := uv.ProjectDirectory(command)
	if err != nil {
		return nil, err
	}
	project, err = configurationDirectory(project)
	if err != nil {
		return nil, err
	}
	for directory := project; ; directory = filepath.Dir(directory) {
		local, err := directorySettings(directory)
		if err != nil {
			return nil, err
		}
		if local != nil {
			mergeSettings(settings, local)
			break
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	return settings, nil
}

func enabled(value string) bool {
	return value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") || strings.EqualFold(value, "on")
}

func readSettings(path string, optional bool) (map[string]any, error) {
	content, err := os.ReadFile(path)
	if optional && (os.IsNotExist(err) || os.IsPermission(err)) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("could not read uv configuration")
	}
	settings := map[string]any{}
	if toml.Unmarshal(content, &settings) != nil {
		return nil, errors.New("could not parse uv configuration")
	}
	// uv resolves index paths relative to each configuration's directory before
	// combining files. Keep that origin when supplying a temporary configuration.
	directory, err := physicalParent(path)
	if err != nil {
		return nil, err
	}
	rebaseIndexes(settings, directory)
	return settings, nil
}

func directorySettings(directory string) (map[string]any, error) {
	settings, err := readSettings(filepath.Join(directory, "uv.toml"), true)
	if settings != nil || err != nil {
		return settings, err
	}
	project, err := readSettings(filepath.Join(directory, "pyproject.toml"), true)
	if err != nil {
		// uv ignores invalid pyproject.toml files during configuration discovery.
		return nil, nil
	}
	tool, _ := project["tool"].(map[string]any)
	settings, _ = tool["uv"].(map[string]any)
	return standaloneSettings(settings, directory), nil
}

func standaloneSettings(settings map[string]any, directory string) map[string]any {
	// These fields belong to pyproject.toml, not the standalone uv config schema.
	for _, key := range []string{"workspace", "sources", "dev-dependencies", "default-groups", "dependency-groups", "managed", "package", "build-backend", "environments", "required-environments", "minimum-libc-version", "conflicts"} {
		delete(settings, key)
	}
	rebaseIndexes(settings, directory)
	return settings
}

// Workspace members inherit configuration from their workspace root.
func configurationDirectory(project string) (string, error) {
	member := project
	foundProject := false
	for directory := project; ; directory = filepath.Dir(directory) {
		content, err := readSettings(filepath.Join(directory, "pyproject.toml"), true)
		if err == nil {
			if content != nil && !foundProject {
				member, foundProject = directory, true
			}
			tool, _ := content["tool"].(map[string]any)
			uv, _ := tool["uv"].(map[string]any)
			workspace, _ := uv["workspace"].(map[string]any)
			if workspace != nil {
				relative, err := filepath.Rel(directory, member)
				if err != nil {
					return "", err
				}
				if relative == "." || (matchesWorkspaceAt(workspace["members"], relative, directory, false) && !matchesWorkspaceAt(workspace["exclude"], relative, directory, true)) {
					return directory, nil
				}
			}
		}
		if directory == filepath.Dir(directory) {
			return project, nil
		}
	}
}

func matchesWorkspaceAt(value any, path, root string, exclusion bool) bool {
	patterns, _ := value.([]any)
	for _, pattern := range patterns {
		if text, ok := pattern.(string); ok {
			target := path
			if filepath.IsAbs(text) {
				target = filepath.Join(root, path)
			}
			segments, valid := workspacePatternSegments(filepath.ToSlash(filepath.Clean(text)))
			if !valid {
				continue
			}
			if exclusion && workspaceExclusion(strings.Join(segments, "/"), filepath.ToSlash(target)) {
				return true
			}
			if !exclusion && workspaceGlob(segments, strings.Split(filepath.ToSlash(target), "/")) {
				return true
			}
		}
	}
	return false
}

// Unlike workspace members, uv exclusion patterns let '*' and '?' cross path
// separators. Character classes retain the translated Rust semantics above.
func workspaceExclusion(pattern, target string) bool {
	pat, name := []rune(pattern), []rune(target)
	type position struct{ pattern, target int }
	seen, matched := map[position]bool{}, map[position]bool{}
	var match func(int, int) bool
	match = func(p, n int) bool {
		key := position{p, n}
		if seen[key] {
			return matched[key]
		}
		seen[key] = true
		result := false
		defer func() { matched[key] = result }()
		if p == len(pat) {
			result = n == len(name)
			return result
		}
		switch pat[p] {
		case '*':
			if p+2 < len(pat) && pat[p+1] == '*' && pat[p+2] == '/' {
				result = match(p+3, n)
				for end := n; !result && end < len(name); end++ {
					if name[end] == '/' {
						result = match(p+3, end+1)
					}
				}
			} else {
				result = match(p+1, n) || (n < len(name) && match(p, n+1))
			}
		case '?':
			result = n < len(name) && match(p+1, n+1)
		case '[':
			end := p + 1
			for end < len(pat) && pat[end] != ']' {
				if pat[end] == '\\' {
					end++
				}
				end++
			}
			if n < len(name) && end < len(pat) {
				character, _ := filepath.Match(string(pat[p:end+1]), string(name[n]))
				result = character && match(end+1, n+1)
			}
		case '\\':
			result = p+1 < len(pat) && n < len(name) && pat[p+1] == name[n] && match(p+2, n+1)
		default:
			result = n < len(name) && pat[p] == name[n] && match(p+1, n+1)
		}
		return result
	}
	return match(0, 0)
}

// Rust glob uses [!...] for negation, treats backslashes literally, and permits
// ']' as the first class member and '-' at either end. Translate to Go's class
// syntax before matching, splitting only on separators outside a class.
func workspacePatternSegments(pattern string) ([]string, bool) {
	var segments []string
	var segment strings.Builder
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '/':
			segments = append(segments, segment.String())
			segment.Reset()
		case '\\':
			segment.WriteString(`\\`)
		case '[':
			segment.WriteByte('[')
			index++
			if index < len(pattern) && pattern[index] == '!' {
				segment.WriteByte('^')
				index++
			}
			start := index
			if index < len(pattern) && pattern[index] == ']' {
				segment.WriteString(`\]`)
				index++
			}
			for index < len(pattern) && pattern[index] != ']' {
				character := pattern[index]
				if character == '\\' || character == '^' || (character == '-' && (index == start || (index+1 < len(pattern) && pattern[index+1] == ']'))) {
					segment.WriteByte('\\')
				}
				segment.WriteByte(character)
				index++
			}
			if index == len(pattern) {
				return nil, false
			}
			segment.WriteByte(']')
		default:
			segment.WriteByte(pattern[index])
		}
	}
	return append(segments, segment.String()), true
}

func workspaceGlob(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == "**" {
		return workspaceGlob(pattern[1:], path) || (len(path) > 0 && workspaceGlob(pattern, path[1:]))
	}
	if len(path) == 0 {
		return false
	}
	matched, _ := filepath.Match(pattern[0], path[0])
	return matched && workspaceGlob(pattern[1:], path[1:])
}

// Higher-precedence scalars replace lower ones; arrays are prepended, matching uv.
func mergeSettings(base, overrides map[string]any) {
	for key, value := range overrides {
		switch typed := value.(type) {
		case map[string]any:
			if existing, ok := base[key].(map[string]any); ok {
				mergeSettings(existing, typed)
				continue
			}
		case []any:
			if existing, ok := base[key].([]any); ok {
				value = append(typed, existing...)
			}
		}
		base[key] = value
	}
}

func rebaseIndexes(settings map[string]any, directory string) {
	rebase := func(value any) any {
		if path, ok := value.(string); ok && path != "" && !strings.Contains(path, ":") {
			return resolvePath(directory, path)
		}
		return value
	}
	if value, ok := settings["index-url"]; ok {
		settings["index-url"] = rebase(value)
	}
	for _, key := range []string{"extra-index-url", "find-links", "index"} {
		values, _ := settings[key].([]any)
		for i, value := range values {
			if index, ok := value.(map[string]any); ok {
				index["url"] = rebase(index["url"])
			} else {
				values[i] = rebase(value)
			}
		}
	}
	if pip, ok := settings["pip"].(map[string]any); ok {
		rebaseIndexes(pip, directory)
	}
}
