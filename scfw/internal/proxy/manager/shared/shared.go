// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package shared contains small mechanics shared by package-manager adapters.
package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const DefaultNPMRegistry = "https://registry.npmjs.org/"
const DefaultPyPIRegistry = "https://pypi.org/simple/"

func CommandOutput(ctx context.Context, executable string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return nil, fmt.Errorf("%w: %s", err, detail)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func ParseURL(name, value string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid %s URL %q", name, value)
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed, nil
}

// ParseNPMJSON extracts npm-compatible registry keys from a JSON object.
func ParseNPMJSON(data []byte) (*url.URL, map[string]*url.URL, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, nil, fmt.Errorf("decode JSON: %w", err)
	}
	defaultValue := DefaultNPMRegistry
	if raw := values["registry"]; raw != nil {
		_ = json.Unmarshal(raw, &defaultValue)
	}
	var structuredRegistries map[string]string
	if raw := values["registries"]; raw != nil && json.Unmarshal(raw, &structuredRegistries) == nil {
		if value := structuredRegistries["default"]; value != "" {
			defaultValue = value
		}
	}
	registry, err := ParseURL("registry", defaultValue)
	if err != nil {
		return nil, nil, err
	}
	named := make(map[string]*url.URL)
	for name, value := range structuredRegistries {
		if name == "default" || value == "" {
			continue
		}
		parsed, parseErr := ParseURL("registries."+name, value)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		if !strings.HasPrefix(name, "@") {
			name = "@" + name
		}
		named[strings.ToLower(name)] = parsed
	}
	for key, raw := range values {
		if !strings.HasPrefix(key, "@") || !strings.HasSuffix(key, ":registry") {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, nil, fmt.Errorf("decode %s: %w", key, err)
		}
		parsed, err := ParseURL(key, value)
		if err != nil {
			return nil, nil, err
		}
		named[strings.ToLower(strings.TrimSuffix(key, ":registry"))] = parsed
	}
	return registry, named, nil
}

func InsertOptions(args, options []string) []string {
	separator := len(args)
	for index, argument := range args {
		if argument == "--" {
			separator = index
			break
		}
	}
	result := append([]string(nil), args[:separator]...)
	result = append(result, options...)
	return append(result, args[separator:]...)
}

// Operation returns the first positional argument after process-wide options.
// optionsWithValue lists options whose following argument must also be skipped.
// It is used only to apply command-safety settings; proxy routing and policy
// evaluation are independent of the returned operation.
func Operation(args []string, optionsWithValue map[string]bool) string {
	positionals := PositionalArguments(args, optionsWithValue)
	if len(positionals) == 0 {
		return ""
	}
	return positionals[0]
}

// PositionalArguments returns lowercase positional arguments after removing
// options and the values of known value-taking options.
func PositionalArguments(args []string, optionsWithValue map[string]bool) []string {
	positionals := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			for _, positional := range args[index+1:] {
				positionals = append(positionals, strings.ToLower(positional))
			}
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positionals = append(positionals, strings.ToLower(argument))
			continue
		}
		name, _, inlineValue := strings.Cut(strings.ToLower(argument), "=")
		if !inlineValue && optionsWithValue[name] {
			index++
		}
	}
	return positionals
}

func SortedNamedOptions(named map[string]string, format func(string, string) string) []string {
	names := make([]string, 0, len(named))
	for name := range named {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, format(name, named[name]))
	}
	return result
}

func OverrideEnvironment(overrides map[string]string, remove ...string) []string {
	removed := make(map[string]bool, len(remove)+len(overrides))
	for _, name := range remove {
		removed[strings.ToLower(name)] = true
	}
	for name := range overrides {
		removed[strings.ToLower(name)] = true
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !removed[strings.ToLower(name)] {
			environment = append(environment, entry)
		}
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		environment = append(environment, name+"="+overrides[name])
	}
	return environment
}
