// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package uv owns uv index discovery and process-local overrides.
package uv

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	pypiecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
)

type Manager struct{}

func (Manager) Name() string { return "uv" }

type uvFile struct {
	Tool struct {
		UV uvConfiguration `toml:"uv"`
	} `toml:"tool"`
	Index             []uvIndex `toml:"index"`
	DefaultIndex      string    `toml:"default-index"`
	KeyringProvider   string    `toml:"keyring-provider"`
	AllowInsecureHost []string  `toml:"allow-insecure-host"`
	Pip               uvPip     `toml:"pip"`
}

type uvConfiguration struct {
	Index             []uvIndex `toml:"index"`
	DefaultIndex      string    `toml:"default-index"`
	KeyringProvider   string    `toml:"keyring-provider"`
	AllowInsecureHost []string  `toml:"allow-insecure-host"`
	Pip               uvPip     `toml:"pip"`
}

type uvPip struct {
	IndexURL        string   `toml:"index-url"`
	ExtraIndexURL   []string `toml:"extra-index-url"`
	KeyringProvider string   `toml:"keyring-provider"`
}

type uvIndex struct {
	Name     string `toml:"name"`
	URL      string `toml:"url"`
	Default  bool   `toml:"default"`
	Explicit bool   `toml:"explicit"`
}

func (Manager) Registries(ctx context.Context, executable string, args []string) (proxy.RegistryConfiguration, error) {
	if os.Getenv("UV_INSECURE_HOST") != "" {
		return proxy.RegistryConfiguration{}, errors.New("uv proxy mode does not support UV_INSECURE_HOST because TLS exceptions cannot be safely widened to every registry")
	}
	configuration, err := effectiveConfiguration()
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	if len(configuration.AllowInsecureHost) > 0 {
		return proxy.RegistryConfiguration{}, errors.New("uv proxy mode does not support allow-insecure-host configuration; configure a trusted CA with SSL_CERT_FILE")
	}
	if os.Getenv("UV_INDEX") == "" && os.Getenv("UV_EXTRA_INDEX_URL") == "" {
		for _, index := range configuration.Index {
			if index.Explicit {
				return proxy.RegistryConfiguration{}, fmt.Errorf("uv proxy mode cannot safely represent explicit index %q", index.Name)
			}
		}
	}
	pipCommand := len(args) > 0 && args[0] == "pip"
	defaultValue := configuration.DefaultIndex
	indexes := indexDefinitions(configuration.Index)
	if pipCommand {
		if configuration.Pip.IndexURL != "" {
			defaultValue = configuration.Pip.IndexURL
		}
		if len(configuration.Pip.ExtraIndexURL) > 0 {
			indexes = append([]string(nil), configuration.Pip.ExtraIndexURL...)
		}
		if configuration.Pip.KeyringProvider != "" {
			configuration.KeyringProvider = configuration.Pip.KeyringProvider
		}
	}
	if provider := os.Getenv("UV_KEYRING_PROVIDER"); provider != "" {
		configuration.KeyringProvider = provider
	}
	if configuration.KeyringProvider != "" && !strings.EqualFold(configuration.KeyringProvider, "disabled") {
		return proxy.RegistryConfiguration{}, errors.New("uv proxy mode does not support keyring authentication; use URL, netrc, or uv auth credentials")
	}
	if value := os.Getenv("UV_INDEX_URL"); value != "" {
		defaultValue = value
	}
	if value := os.Getenv("UV_DEFAULT_INDEX"); value != "" {
		defaultValue = value
	}
	if value := os.Getenv("UV_EXTRA_INDEX_URL"); value != "" {
		indexes = strings.Fields(value)
	}
	if value := os.Getenv("UV_INDEX"); value != "" {
		indexes = strings.Fields(value)
	}
	if defaultValue == "" {
		defaultValue = shared.DefaultPyPIRegistry
	}
	registry, err := shared.ParseURL("uv default-index", defaultValue)
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	named := make(map[string]*url.URL)
	for index, definition := range indexes {
		name, value, found := strings.Cut(definition, "=")
		if !found {
			name, value = "index-"+string(rune('a'+index)), definition
		}
		parsed, parseErr := shared.ParseURL("uv index", value)
		if parseErr != nil {
			return proxy.RegistryConfiguration{}, parseErr
		}
		named[name] = parsed
	}
	registries := []*url.URL{registry}
	for _, index := range named {
		registries = append(registries, index)
	}
	credentials, err := loadStoredCredentials(ctx, executable, registries)
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	return proxy.RegistryConfiguration{Default: registry, Named: named, Handler: pypiecosystem.Handler{}, Credentials: credentials, UseNetrc: true, CAFile: os.Getenv("SSL_CERT_FILE")}, nil
}

func effectiveConfiguration() (uvConfiguration, error) {
	paths, err := uvConfigPaths()
	if err != nil {
		return uvConfiguration{}, err
	}
	var merged uvConfiguration
	for _, path := range paths {
		configuration, readErr := readConfiguration(path)
		if readErr != nil {
			return uvConfiguration{}, readErr
		}
		merged = mergeConfiguration(merged, configuration)
	}
	return merged, nil
}

func uvConfigPaths() ([]string, error) {
	if explicit := os.Getenv("UV_CONFIG_FILE"); explicit != "" {
		return []string{explicit}, nil
	}
	if environmentEnabled("UV_NO_CONFIG") {
		return nil, nil
	}
	paths := make([]string, 0, 3)
	if !environmentEnabled("UV_NO_SYSTEM_CONFIG") {
		for _, directory := range systemConfigDirectories() {
			path := filepath.Join(directory, "uv", "uv.toml")
			if _, err := os.Stat(path); err == nil {
				paths = append(paths, path)
				break
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
	}
	if path := userConfigPath(); path != "" {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	directory, _ := os.Getwd()
	for {
		uvPath := filepath.Join(directory, "uv.toml")
		if _, err := os.Stat(uvPath); err == nil {
			return append(paths, uvPath), nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		projectPath := filepath.Join(directory, "pyproject.toml")
		if contents, err := os.ReadFile(projectPath); err == nil {
			var document map[string]any
			if toml.Unmarshal(contents, &document) == nil && hasToolUV(document) {
				return append(paths, projectPath), nil
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return paths, nil
		}
		directory = parent
	}
}

func readConfiguration(path string) (uvConfiguration, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return uvConfiguration{}, err
	}
	var file uvFile
	if err := toml.Unmarshal(contents, &file); err != nil {
		return uvConfiguration{}, err
	}
	if filepath.Base(path) == "pyproject.toml" {
		return normalizeConfiguration(file.Tool.UV), nil
	}
	return normalizeConfiguration(uvConfiguration{Index: file.Index, DefaultIndex: file.DefaultIndex, KeyringProvider: file.KeyringProvider, AllowInsecureHost: file.AllowInsecureHost, Pip: file.Pip}), nil
}

func normalizeConfiguration(configuration uvConfiguration) uvConfiguration {
	if configuration.DefaultIndex == "" {
		for _, index := range configuration.Index {
			if index.Default && index.URL != "" {
				configuration.DefaultIndex = index.URL
				break
			}
		}
	}
	return configuration
}

func mergeConfiguration(lower, higher uvConfiguration) uvConfiguration {
	result := lower
	result.Index = append(append([]uvIndex(nil), higher.Index...), lower.Index...)
	if higher.DefaultIndex != "" {
		result.DefaultIndex = higher.DefaultIndex
	}
	if higher.KeyringProvider != "" {
		result.KeyringProvider = higher.KeyringProvider
	}
	result.AllowInsecureHost = append(append([]string(nil), higher.AllowInsecureHost...), lower.AllowInsecureHost...)
	result.Pip.ExtraIndexURL = append(append([]string(nil), higher.Pip.ExtraIndexURL...), lower.Pip.ExtraIndexURL...)
	if higher.Pip.IndexURL != "" {
		result.Pip.IndexURL = higher.Pip.IndexURL
	}
	if higher.Pip.KeyringProvider != "" {
		result.Pip.KeyringProvider = higher.Pip.KeyringProvider
	}
	return result
}

type credentialsFile struct {
	Credentials []storedCredential `toml:"credential"`
}

type storedCredential struct {
	Service  string `toml:"service"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	Scheme   string `toml:"scheme"`
}

func loadStoredCredentials(ctx context.Context, executable string, registries []*url.URL) (map[string]proxy.RegistryCredential, error) {
	directory, err := shared.CommandOutput(ctx, executable, "auth", "dir")
	if err != nil {
		// Older uv releases predate the credentials store and rely on URL or
		// netrc authentication, both of which are handled separately.
		return nil, nil
	}
	contents, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(directory)), "credentials.toml"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var file credentialsFile
	if err := toml.Unmarshal(contents, &file); err != nil {
		return nil, err
	}
	credentials := make(map[string]proxy.RegistryCredential)
	for _, credential := range file.Credentials {
		service, parseErr := url.Parse(credential.Service)
		if parseErr != nil || !matchesRegistry(service, registries) || !strings.EqualFold(credential.Scheme, "basic") {
			continue
		}
		credentials[service.String()] = proxy.RegistryCredential{Username: credential.Username, Password: credential.Password}
	}
	return credentials, nil
}

func matchesRegistry(service *url.URL, registries []*url.URL) bool {
	if service == nil || service.Host == "" {
		return false
	}
	for _, registry := range registries {
		if strings.EqualFold(service.Scheme, registry.Scheme) && strings.EqualFold(service.Host, registry.Host) &&
			(strings.HasPrefix(registry.Path, service.Path) || strings.HasPrefix(service.Path, registry.Path)) {
			return true
		}
	}
	return false
}

func indexDefinitions(indexes []uvIndex) []string {
	definitions := make([]string, 0, len(indexes))
	for position, index := range indexes {
		if index.URL == "" {
			continue
		}
		name := index.Name
		if name == "" {
			name = "index-" + string(rune('a'+position))
		}
		definitions = append(definitions, name+"="+index.URL)
	}
	return definitions
}

func hasToolUV(document map[string]any) bool {
	tool, _ := document["tool"].(map[string]any)
	_, ok := tool["uv"]
	return ok
}

func environmentEnabled(name string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return value != "" && value != "0" && value != "false" && value != "no"
}

func systemConfigDirectories() []string {
	if value := os.Getenv("XDG_CONFIG_DIRS"); value != "" {
		return filepath.SplitList(value)
	}
	return []string{"/etc"}
}

func userConfigPath() string {
	if directory := os.Getenv("XDG_CONFIG_HOME"); directory != "" {
		return filepath.Join(directory, "uv", "uv.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "uv", "uv.toml")
}

func (Manager) Prepare(_ string, args []string, registryURL string, named map[string]string) (proxy.PreparedCommand, error) {
	projectCommand := len(args) > 0 && args[0] == "sync"
	indexes := shared.SortedNamedOptions(named, func(name, value string) string {
		if projectCommand {
			// Project source pins require the index name. uv accepts name=url in
			// UV_INDEX for project commands even though pip-style commands accept
			// URLs only.
			return name + "=" + value
		}
		return value
	})
	return proxy.PreparedCommand{
		Args: func() []string {
			if len(args) > 0 && args[0] == "sync" {
				return shared.InsertOptions(args, []string{"--frozen"})
			}
			return args
		}(),
		Env: shared.OverrideEnvironment(map[string]string{
			"UV_DEFAULT_INDEX": registryURL,
			"UV_INDEX":         strings.Join(indexes, " "),
		}, "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"),
	}, nil
}
