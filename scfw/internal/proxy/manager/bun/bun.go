// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package bun owns Bun registry discovery and ephemeral bunfig generation.
package bun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	npmecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
)

type Manager struct{ configuration map[string]any }

func (Manager) Name() string { return "bun" }

func (manager *Manager) Registries(_ context.Context, _ string, _ []string) (proxy.RegistryConfiguration, error) {
	registryValue := os.Getenv("BUN_CONFIG_REGISTRY")
	namedValues := make(map[string]string)
	manager.configuration = make(map[string]any)
	for _, path := range bunConfigurationFiles() {
		if filepath.Base(path) == ".npmrc" {
			loadNPMRC(path, &registryValue, namedValues)
		} else {
			loadBunfig(path, manager.configuration, &registryValue, namedValues)
		}
	}
	if value := os.Getenv("BUN_CONFIG_REGISTRY"); value != "" {
		registryValue = value
	}
	if registryValue == "" {
		registryValue = shared.DefaultNPMRegistry
	}
	registry, err := shared.ParseURL("Bun registry", registryValue)
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	named := make(map[string]*url.URL, len(namedValues))
	for name, value := range namedValues {
		parsed, parseErr := shared.ParseURL("Bun scope "+name, value)
		if parseErr != nil {
			return proxy.RegistryConfiguration{}, parseErr
		}
		named[name] = parsed
	}
	configuration := proxy.RegistryConfiguration{Default: registry, Named: named, Handler: npmecosystem.Handler{}, UseNPMCredentials: true}
	install, _ := manager.configuration["install"].(map[string]any)
	configuration.CAFile, _ = install["cafile"].(string)
	configuration.CACertificates = stringValues(install["ca"])
	return configuration, nil
}

func stringValues(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return values
	default:
		return nil
	}
}

func bunConfigurationFiles() []string {
	result := make([]string, 0, 4)
	if home, err := os.UserHomeDir(); err == nil {
		result = append(result, filepath.Join(home, ".npmrc"), filepath.Join(home, ".bunfig.toml"))
	}
	if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
		result = append(result, filepath.Join(configHome, ".bunfig.toml"))
	}
	if directory, err := os.Getwd(); err == nil {
		result = append(result, filepath.Join(directory, ".npmrc"), filepath.Join(directory, "bunfig.toml"))
	}
	return result
}

func loadNPMRC(path string, registry *string, scopes map[string]string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !found || strings.HasPrefix(key, "#") || strings.HasPrefix(key, ";") {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "registry" {
			*registry = value
		} else if strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry") {
			scopes[strings.TrimSuffix(key, ":registry")] = value
		}
	}
}

func loadBunfig(path string, configuration map[string]any, registry *string, scopes map[string]string) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var document map[string]any
	if toml.Unmarshal(contents, &document) != nil {
		return
	}
	mergeMaps(configuration, document)
	install, _ := document["install"].(map[string]any)
	if value := bunRegistryURL(install["registry"]); value != "" {
		*registry = value
	}
	if configuredScopes, ok := install["scopes"].(map[string]any); ok {
		for scope, raw := range configuredScopes {
			if value := bunRegistryURL(raw); value != "" {
				scopes["@"+strings.TrimPrefix(scope, "@")] = value
			}
		}
	}
}

func bunRegistryURL(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if object, ok := value.(map[string]any); ok {
		text, _ := object["url"].(string)
		return text
	}
	return ""
}

func mergeMaps(destination, source map[string]any) {
	for key, value := range source {
		if sourceMap, ok := value.(map[string]any); ok {
			destinationMap, _ := destination[key].(map[string]any)
			if destinationMap == nil {
				destinationMap = make(map[string]any)
				destination[key] = destinationMap
			}
			mergeMaps(destinationMap, sourceMap)
			continue
		}
		destination[key] = value
	}
}

func (manager *Manager) Prepare(_ string, args []string, registryURL string, named map[string]string) (proxy.PreparedCommand, error) {
	file, err := os.CreateTemp("", "scfw-bunfig-*.toml")
	if err != nil {
		return proxy.PreparedCommand{}, fmt.Errorf("create temporary Bun configuration: %w", err)
	}
	cleanup := func() error { return errors.Join(file.Close(), os.Remove(file.Name())) }
	if err := file.Chmod(0o600); err != nil {
		return proxy.PreparedCommand{}, errors.Join(err, cleanup())
	}
	install, _ := manager.configuration["install"].(map[string]any)
	if install == nil {
		install = make(map[string]any)
		manager.configuration["install"] = install
	}
	install["registry"] = bunProxyRegistry(install["registry"], registryURL)
	originalScopes, _ := install["scopes"].(map[string]any)
	scopes := make(map[string]any, len(named))
	for name, value := range named {
		scope := strings.TrimPrefix(name, "@")
		scopes[scope] = bunProxyRegistry(originalScopes[scope], value)
	}
	install["scopes"] = scopes
	contents, err := toml.Marshal(manager.configuration)
	if err != nil {
		return proxy.PreparedCommand{}, errors.Join(err, cleanup())
	}
	if _, err := file.Write(contents); err != nil {
		return proxy.PreparedCommand{}, errors.Join(err, cleanup())
	}
	if err := file.Close(); err != nil {
		return proxy.PreparedCommand{}, errors.Join(err, os.Remove(file.Name()))
	}
	options := []string(nil)
	operation := shared.Operation(args, map[string]bool{"--config": true, "--cwd": true})
	if operation == "install" || operation == "i" {
		options = append(options, "--frozen-lockfile")
	}
	return proxy.PreparedCommand{
		Args:    append([]string{"--config=" + file.Name()}, shared.InsertOptions(args, options)...),
		Env:     shared.OverrideEnvironment(nil, "BUN_CONFIG_REGISTRY"),
		Cleanup: func() error { return os.Remove(file.Name()) },
	}, nil
}

func bunProxyRegistry(original any, proxyURL string) any {
	if object, ok := original.(map[string]any); ok {
		result := make(map[string]any, len(object)+1)
		for key, value := range object {
			result[key] = value
		}
		result["url"] = proxyURL
		return result
	}
	return proxyURL
}
