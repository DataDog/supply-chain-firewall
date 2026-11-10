// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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
	repositoryOrder  []string
	global           *poetrySettings
}

// readPoetrySettings reads configuration without invoking Poetry or creating
// its configuration directories. auth.toml also stores certificate settings.
func readPoetrySettings(command []string) (poetrySettings, error) {
	command = poetryOwnArguments(command)
	settings := poetrySettings{values: map[string]any{}}
	directory, err := resolvePoetryProjectDir(command)
	if err != nil {
		return settings, err
	}
	// Poetry changes directories before opening relative TLS paths. Resolve the
	// original directory before Abs can collapse '..' across a symlink.
	if physical, resolveErr := filepath.EvalSymlinks(directory); resolveErr == nil {
		settings.workingDirectory = physical
	} else {
		settings.workingDirectory = directory
	}
	settings.workingDirectory, err = filepath.Abs(settings.workingDirectory)
	if err != nil {
		return settings, err
	}
	directory, err = poetryProjectDirectory(command)
	if err != nil {
		return settings, err
	}
	// Poetry finds the nearest containing project, including from subdirectories.
	for {
		data, err := readPoetryTOML(directory + string(filepath.Separator) + "pyproject.toml")
		if err != nil {
			return settings, err
		}
		if data != nil {
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
				}
				if name != "" {
					settings.sources = append(settings.sources, poetrySource{Name: name, URL: address, Priority: priority})
				}
			}
			break
		}
		parent := poetryParentDirectory(directory)
		if parent == directory {
			settings.projectDirectory = settings.workingDirectory
			break
		}
		directory = parent
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
	for index, path := range []string{filepath.Join(configDirectory, "config.toml"), filepath.Join(configDirectory, "auth.toml"), settings.projectDirectory + string(filepath.Separator) + "poetry.toml"} {
		if index == 2 {
			global := settings
			global.values = clonePoetryConfiguration(settings.values)
			global.repositoryOrder = slices.Clone(settings.repositoryOrder)
			settings.global = &global
		}
		data, raw, err := readPoetryDocument(path)
		if err != nil {
			return settings, err
		}
		mergePoetryConfiguration(settings.values, data)
		for _, name := range poetryRepositoryNames(raw) {
			if !slices.Contains(settings.repositoryOrder, name) {
				settings.repositoryOrder = append(settings.repositoryOrder, name)
			}
		}
	}
	return settings, nil
}

func readPoetryTOML(path string) (map[string]any, error) {
	value, _, err := readPoetryDocument(path)
	return value, err
}

func readPoetryDocument(path string) (map[string]any, []byte, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPoetryConfigurationBytes {
		return nil, nil, errors.New("could not read Poetry configuration")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("could not read Poetry configuration")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxPoetryConfigurationBytes+1))
	if err != nil || len(data) > maxPoetryConfigurationBytes {
		return nil, nil, errors.New("could not read Poetry configuration")
	}
	var value map[string]any
	if err := toml.Unmarshal(data, &value); err != nil {
		return nil, nil, errors.New("invalid Poetry configuration")
	}
	return value, data, nil
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

func clonePoetryConfiguration(source map[string]any) map[string]any {
	copy := make(map[string]any, len(source))
	for key, value := range source {
		if nested, ok := value.(map[string]any); ok {
			value = clonePoetryConfiguration(nested)
		}
		copy[key] = value
	}
	return copy
}

var poetryConfigurationReference = regexp.MustCompile(`\{(.+?)\}`)

func (s poetrySettings) get(keys ...string) any {
	return s.process(s.raw(keys...), 0)
}

func (s poetrySettings) process(value any, depth int) any {
	budget := maxPoetryConfigurationBytes
	processed := s.processValue(value, depth, &budget)
	if processed == nil {
		return value
	}
	return processed
}

func (s poetrySettings) processValue(value any, depth int, budget *int) any {
	text, ok := value.(string)
	if !ok {
		return value
	}
	if depth >= 16 || len(text) > *budget {
		return nil
	}
	*budget -= len(text)
	return poetryConfigurationReference.ReplaceAllStringFunc(text, func(reference string) string {
		replacement := s.processValue(s.raw(strings.Split(reference[1:len(reference)-1], ".")...), depth+1, budget)
		if replacement == nil {
			return reference
		}
		if boolean, ok := replacement.(bool); ok {
			if boolean {
				return "True"
			}
			return "False"
		}
		return fmt.Sprint(replacement)
	})
}

func (s poetrySettings) raw(keys ...string) any {
	env := "POETRY_" + poetryEnvironmentName(strings.Join(keys, "_"))
	if value, present := os.LookupEnv(env); present {
		return value
	}
	var value any = s.values
	for _, key := range keys {
		table, ok := value.(map[string]any)
		if !ok {
			value = nil
			break
		}
		value = table[key]
	}
	if value == nil && slices.Equal(keys, []string{"virtualenvs", "path"}) {
		return "{cache-dir}/virtualenvs"
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
	// Config.process expands references, not shell variables or tildes.
	path, _ := s.process(value, 0).(string)
	return s.workingPath(path)
}

// workingPath preserves literal Requests environment paths; unlike Poetry
// certificate settings, those paths do not expand configuration placeholders.
func (s poetrySettings) workingPath(path string) string {
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		// Join would collapse '..' before the filesystem follows symlinks.
		path = s.workingDirectory + string(os.PathSeparator) + path
	}
	if physical, err := filepath.EvalSymlinks(path); err == nil {
		return physical
	}
	// Missing or invalid unused CA paths must keep their deferred validation.
	return path
}
