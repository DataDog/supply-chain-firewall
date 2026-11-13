// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// bunSettings are the network settings Bun applies to one command. Bun only
// takes its upstream proxy from the environment; .npmrc proxy keys and
// bunfig's [install] proxy do not route its registry traffic.
type bunSettings struct {
	HTTPS, HTTP, NoProxy string
	CAFiles, CA          []string
	Registries           []string
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func (b Bun) settings(command []string) (bunSettings, parsedCommand, error) {
	parsed := parseCommand(b.installed.Minor, b.bunx, command)
	cwd, err := os.Getwd()
	if err != nil {
		return bunSettings{}, parsed, errors.New("could not resolve bun directory")
	}
	if parsed.cwd != "" {
		cwd = absolute(cwd, parsed.cwd)
	}
	settings := bunSettings{
		// Bun prefers the lowercase variables.
		HTTPS:   firstEnv("https_proxy", "HTTPS_PROXY"),
		HTTP:    firstEnv("http_proxy", "HTTP_PROXY"),
		NoProxy: firstEnv("no_proxy", "NO_PROXY"),
		CA:      parsed.cas,
	}
	for _, file := range parsed.cafiles {
		settings.CAFiles = append(settings.CAFiles, absolute(cwd, file))
	}
	settings.Registries = append(settings.Registries, firstEnv("BUN_CONFIG_REGISTRY"), firstEnv("NPM_CONFIG_REGISTRY", "npm_config_registry"))
	settings.Registries = append(settings.Registries, parsed.registries...)

	env := nodeproxy.LookupEnvironment(os.Environ())
	home, _ := os.UserHomeDir()
	userNpmrc := os.Getenv("NPM_CONFIG_USERCONFIG")
	if userNpmrc == "" {
		userNpmrc = filepath.Join(home, ".npmrc")
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			userNpmrc = filepath.Join(xdg, ".npmrc")
		}
	}
	npmrcs := []string{userNpmrc}
	if root := projectRoot(cwd); root != "" {
		npmrcs = append(npmrcs, filepath.Join(root, ".npmrc"))
	}
	for _, path := range npmrcs {
		config, err := nodeproxy.LoadNpmrc(path, env)
		if err != nil {
			continue
		}
		for key, values := range config {
			switch {
			case key == "registry" || strings.HasSuffix(key, ":registry"):
				settings.Registries = append(settings.Registries, values...)
			case key == "ca" || key == "ca[]":
				settings.CA = append(settings.CA, values...)
			case key == "cafile":
				for _, value := range values {
					settings.CAFiles = append(settings.CAFiles, absolute(filepath.Dir(path), value))
				}
			}
		}
	}

	global := filepath.Join(home, ".bunfig.toml")
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		global = filepath.Join(xdg, ".bunfig.toml")
	}
	project := filepath.Join(cwd, "bunfig.toml")
	if parsed.config != "" {
		project = absolute(cwd, parsed.config)
	}
	for _, path := range []string{global, project} {
		settings.addBunfig(path)
	}
	return settings, parsed, nil
}

func absolute(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// projectRoot returns the nearest directory at or above dir with package.json.
func projectRoot(dir string) string {
	for current := dir; ; current = filepath.Dir(current) {
		if regularFile(filepath.Join(current, "package.json")) {
			return current
		}
		if filepath.Dir(current) == current {
			return ""
		}
	}
}

// addBunfig reads bunfig's registries and CA settings. An unreadable or
// malformed file adds nothing; Bun reports it itself.
func (s *bunSettings) addBunfig(path string) {
	data, err := nodeproxy.ReadConfigFile(path)
	if err != nil {
		return
	}
	var config struct {
		Install struct {
			Registry any            `toml:"registry"`
			Scopes   map[string]any `toml:"scopes"`
			CA       any            `toml:"ca"`
			CAFile   string         `toml:"cafile"`
		} `toml:"install"`
	}
	if toml.Unmarshal(data, &config) != nil {
		return
	}
	expand := func(value string) string { return os.Expand(value, os.Getenv) }
	registry := func(value any) {
		switch typed := value.(type) {
		case string:
			s.Registries = append(s.Registries, expand(typed))
		case map[string]any:
			if url, ok := typed["url"].(string); ok {
				s.Registries = append(s.Registries, expand(url))
			}
		}
	}
	registry(config.Install.Registry)
	for _, scope := range config.Install.Scopes {
		registry(scope)
	}
	switch typed := config.Install.CA.(type) {
	case string:
		s.CA = append(s.CA, expand(typed))
	case []any:
		for _, item := range typed {
			if value, ok := item.(string); ok {
				s.CA = append(s.CA, expand(value))
			}
		}
	}
	if config.Install.CAFile != "" {
		s.CAFiles = append(s.CAFiles, absolute(filepath.Dir(path), expand(config.Install.CAFile)))
	}
}
