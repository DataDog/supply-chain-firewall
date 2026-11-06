// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"net/url"
	"os"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
)

func (uv UV) PyPIClassifierOptions(command []string) (pypi.RequestClassifierOptions, error) {
	settings, err := uv.settings(command)
	if err != nil {
		return pypi.RequestClassifierOptions{}, err
	}
	var result pypi.RequestClassifierOptions
	add := func(value string) {
		// --index accepts name=URL, while URL arguments may contain '=' too.
		if name, named, ok := strings.Cut(value, "="); ok && !strings.Contains(name, ":") {
			value = named
		}
		parsed, err := url.Parse(value)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			result.SimpleIndexURLs = append(result.SimpleIndexURLs, value)
		}
	}
	addSettings := func(settings map[string]any) {
		if value, ok := settings["index-url"].(string); ok {
			add(value)
		}
		for _, key := range []string{"index", "extra-index-url"} {
			values, _ := settings[key].([]any)
			for _, value := range values {
				if index, ok := value.(map[string]any); ok {
					value = index["url"]
				}
				if text, ok := value.(string); ok {
					add(text)
				}
			}
		}
	}
	addSettings(settings)
	options := parseOptions(command)
	if options.command == "pip" {
		pip, _ := settings["pip"].(map[string]any)
		addSettings(pip)
	}
	for _, key := range []string{"UV_INDEX", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"} {
		for _, value := range strings.Fields(os.Getenv(key)) {
			add(value)
		}
	}
	for _, option := range options.options {
		switch option.name {
		case "index", "default-index", "index-url", "extra-index-url":
			add(option.value)
		}
	}
	return result, nil
}
