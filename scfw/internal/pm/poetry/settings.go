// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const maxPoetryConfigurationBytes = 4 << 20

type poetrySource struct{ Name, URL, Priority string }

type poetrySettings struct {
	projectDirectory string
	workingDirectory string
	values           map[string]any
	sources          []poetrySource
	gitURLs          []string
}

// readPoetrySettings reads configuration without invoking Poetry or creating
// its configuration directories. auth.toml also stores certificate settings.
func readPoetrySettings(command []string) (poetrySettings, error) {
	settings := poetrySettings{values: map[string]any{}}
	directory, err := resolvePoetryProjectDir(command)
	if err != nil {
		return settings, err
	}
	settings.workingDirectory, err = filepath.Abs(directory)
	if err != nil {
		return settings, err
	}
	directory = settings.workingDirectory
	for i, argument := range command {
		if argument == "--" {
			break
		}
		project := ""
		switch {
		case argument == "--project" || argument == "-P":
			if i+1 < len(command) {
				project = command[i+1]
			}
		case strings.HasPrefix(argument, "--project="):
			project = strings.TrimPrefix(argument, "--project=")
		case strings.HasPrefix(argument, "-P"):
			project = strings.TrimPrefix(strings.TrimPrefix(argument, "-P"), "=")
		}
		if project != "" {
			if filepath.IsAbs(project) {
				directory = project
			} else {
				directory = filepath.Join(directory, project)
			}
			break
		}
	}
	// Poetry finds the nearest containing project, including from subdirectories.
	for {
		data, err := readPoetryTOML(filepath.Join(directory, "pyproject.toml"))
		if err != nil {
			return settings, err
		}
		if data != nil {
			settings.gitURLs = append(settings.gitURLs, poetryGitURLs(data)...)
			settings.projectDirectory = directory
			tool, _ := data["tool"].(map[string]any)
			poetry, _ := tool["poetry"].(map[string]any)
			sources, _ := poetry["source"].([]any)
			for _, item := range sources {
				source, _ := item.(map[string]any)
				name, _ := source["name"].(string)
				address, _ := source["url"].(string)
				priority, _ := source["priority"].(string)
				if priority == "" {
					priority = "primary"
					if source["secondary"] == true {
						priority = "supplemental"
					}
				}
				if name != "" {
					settings.sources = append(settings.sources, poetrySource{Name: strings.ToLower(name), URL: address, Priority: priority})
				}
			}
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			settings.projectDirectory = settings.workingDirectory
			break
		}
		directory = parent
	}
	lock, err := readPoetryTOML(filepath.Join(settings.projectDirectory, "poetry.lock"))
	if err != nil {
		return settings, err
	}
	settings.gitURLs = append(settings.gitURLs, poetryGitURLs(lock)...)
	for _, argument := range command {
		settings.gitURLs = append(settings.gitURLs, poetryGitURLs(argument)...)
	}
	configDirectory := os.Getenv("POETRY_CONFIG_DIR")
	if configDirectory == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return settings, err
		}
		if runtime.GOOS == "darwin" {
			configDirectory = filepath.Join(home, "Library", "Application Support", "pypoetry")
		} else {
			base := os.Getenv("XDG_CONFIG_HOME")
			if base == "" {
				base = filepath.Join(home, ".config")
			}
			configDirectory = filepath.Join(base, "pypoetry")
		}
	}
	for _, path := range []string{filepath.Join(configDirectory, "config.toml"), filepath.Join(configDirectory, "auth.toml"), filepath.Join(settings.projectDirectory, "poetry.toml")} {
		data, err := readPoetryTOML(path)
		if err != nil {
			return settings, err
		}
		mergePoetryConfiguration(settings.values, data)
	}
	// Repository names are normalized by Poetry's repository objects.
	if certificates, ok := settings.values["certificates"].(map[string]any); ok {
		normalized := map[string]any{}
		for name, value := range certificates {
			normalized[strings.ToLower(name)] = value
		}
		settings.values["certificates"] = normalized
	}
	return settings, nil
}

func readPoetryTOML(path string) (map[string]any, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPoetryConfigurationBytes {
		return nil, errors.New("could not read Poetry configuration")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not read Poetry configuration")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxPoetryConfigurationBytes+1))
	if err != nil || len(data) > maxPoetryConfigurationBytes {
		return nil, errors.New("could not read Poetry configuration")
	}
	var value map[string]any
	if err := toml.Unmarshal(data, &value); err != nil {
		return nil, errors.New("invalid Poetry configuration")
	}
	return value, nil
}

func mergePoetryConfiguration(target, source map[string]any) {
	for key, value := range source {
		existing, ok := target[key].(map[string]any)
		nested, isMap := value.(map[string]any)
		if ok && isMap {
			mergePoetryConfiguration(existing, nested)
		} else {
			target[key] = value
		}
	}
}

func (s poetrySettings) get(keys ...string) any {
	env := "POETRY_" + strings.ToUpper(strings.ReplaceAll(strings.Join(keys, "_"), "-", "_"))
	if value, present := os.LookupEnv(env); present {
		return value
	}
	var value any = s.values
	for _, key := range keys {
		table, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = table[key]
	}
	if value == nil && len(keys) == 1 {
		home, _ := os.UserHomeDir()
		switch keys[0] {
		case "cache-dir":
			base, err := os.UserCacheDir()
			if err == nil {
				return filepath.Join(base, "pypoetry")
			}
		case "data-dir":
			if base := os.Getenv("POETRY_HOME"); base != "" {
				if strings.HasPrefix(base, "~/") {
					return filepath.Join(home, base[2:])
				}
				return base
			}
			if runtime.GOOS == "darwin" {
				return filepath.Join(home, "Library", "Application Support", "pypoetry")
			}
			base := os.Getenv("XDG_DATA_HOME")
			if base == "" {
				base = filepath.Join(home, ".local", "share")
			}
			return filepath.Join(base, "pypoetry")
		}
	}
	return value
}

func (s poetrySettings) certificatePath(value any) string {
	path, _ := value.(string)
	// Config.process expands references, not shell variables or tildes.
	for iteration := 0; iteration < 8; iteration++ {
		before := path
		for _, key := range []string{"cache-dir", "data-dir"} {
			if replacement, ok := s.get(key).(string); ok {
				path = strings.ReplaceAll(path, "{"+key+"}", replacement)
			}
		}
		if path == before {
			break
		}
	}
	if path != "" && !filepath.IsAbs(path) {
		path = filepath.Join(s.workingDirectory, path)
	}
	return path
}

func poetryBoolean(value any, fallback bool) bool {
	if value == nil {
		return fallback
	}
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	text, _ := value.(string)
	return strings.EqualFold(text, "true") || text == "1" || strings.EqualFold(text, "yes") || strings.EqualFold(text, "on")
}

// Known VCS URLs let setup diagnose old clients before a TLS handshake fails.
func poetryGitURLs(value any) []string {
	var result []string
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			if text, ok := item.(string); ok && (key == "git" || (key == "url" && value["type"] == "git")) && (strings.HasPrefix(text, "https://") || strings.HasPrefix(text, "http://")) {
				result = append(result, text)
			}
			result = append(result, poetryGitURLs(item)...)
		}
	case []any:
		for _, item := range value {
			result = append(result, poetryGitURLs(item)...)
		}
	case string:
		if index := strings.Index(value, "git+http"); index >= 0 {
			text := value[index+4:]
			text, _, _ = strings.Cut(text, " ")
			text, _, _ = strings.Cut(text, ";")
			result = append(result, text)
		}
	}
	return result
}
