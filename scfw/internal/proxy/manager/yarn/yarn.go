// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package yarn owns Yarn Classic and modern Yarn registry configuration.
package yarn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	npmecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
)

type Manager struct {
	modern       bool
	modernScopes map[string]map[string]any
}

func (Manager) Name() string { return "yarn" }

func (manager *Manager) Registries(ctx context.Context, executable string, _ []string) (proxy.RegistryConfiguration, error) {
	if registry, named, scopes, err := loadModern(ctx, executable); err == nil {
		manager.modern = true
		manager.modernScopes = scopes
		configuration := proxy.RegistryConfiguration{Default: registry, Named: named, Handler: npmecosystem.Handler{}, Credentials: make(map[string]proxy.RegistryCredential), UseNPMCredentials: true}
		if token, tokenErr := modernString(ctx, executable, "npmAuthToken"); tokenErr == nil && token != "" {
			configuration.Credentials[registry.String()] = proxy.RegistryCredential{BearerToken: token}
		} else if ident, identErr := modernString(ctx, executable, "npmAuthIdent"); identErr == nil {
			if username, password, found := strings.Cut(ident, ":"); found {
				configuration.Credentials[registry.String()] = proxy.RegistryCredential{Username: username, Password: password}
			}
		}
		for scope, values := range scopes {
			upstream := named["@"+scope]
			if upstream == nil {
				continue
			}
			if token, ok := values["npmAuthToken"].(string); ok && token != "" {
				configuration.Credentials[upstream.String()] = proxy.RegistryCredential{BearerToken: token}
			} else if ident, ok := values["npmAuthIdent"].(string); ok {
				if username, password, found := strings.Cut(ident, ":"); found {
					configuration.Credentials[upstream.String()] = proxy.RegistryCredential{Username: username, Password: password}
				}
			}
		}
		configuration.CAFile, _ = modernString(ctx, executable, "httpsCaFilePath")
		configuration.ClientCertificateFile, _ = modernString(ctx, executable, "httpsCertFilePath")
		configuration.ClientKeyFile, _ = modernString(ctx, executable, "httpsKeyFilePath")
		if strictSSL, strictErr := modernBool(ctx, executable, "enableStrictSsl"); strictErr == nil {
			configuration.InsecureTLS = !strictSSL
		}
		return configuration, nil
	}
	output, err := shared.CommandOutput(ctx, executable, "config", "list", "--json")
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	registry, named, err := parseClassic(output)
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	values, _ := parseClassicValues(output)
	configuration := proxy.RegistryConfiguration{Default: registry, Named: named, Handler: npmecosystem.Handler{}, UseNPMCredentials: true}
	_ = json.Unmarshal(values["cafile"], &configuration.CAFile)
	if json.Unmarshal(values["ca"], &configuration.CACertificates) != nil {
		var certificate string
		if json.Unmarshal(values["ca"], &certificate) == nil && certificate != "" {
			configuration.CACertificates = []string{certificate}
		}
	}
	var strictSSL bool
	if json.Unmarshal(values["strict-ssl"], &strictSSL) == nil {
		configuration.InsecureTLS = !strictSSL
	}
	return configuration, nil
}

func modernString(ctx context.Context, executable, setting string) (string, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "get", setting, "--json", "--no-redacted")
	if err != nil {
		return "", err
	}
	var value *string
	if err := json.Unmarshal(output, &value); err != nil || value == nil {
		return "", err
	}
	return *value, nil
}

func modernBool(ctx context.Context, executable, setting string) (bool, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "get", setting, "--json")
	if err != nil {
		return false, err
	}
	var value bool
	return value, json.Unmarshal(output, &value)
}

func loadModern(ctx context.Context, executable string) (*url.URL, map[string]*url.URL, map[string]map[string]any, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "get", "npmRegistryServer", "--json")
	if err != nil {
		return nil, nil, nil, err
	}
	var registryValue string
	if err := json.Unmarshal(output, &registryValue); err != nil {
		return nil, nil, nil, err
	}
	registry, err := shared.ParseURL("npmRegistryServer", registryValue)
	if err != nil {
		return nil, nil, nil, err
	}
	named := make(map[string]*url.URL)
	scopes := make(map[string]map[string]any)
	scopesOutput, err := shared.CommandOutput(ctx, executable, "config", "get", "npmScopes", "--json", "--no-redacted")
	if err == nil {
		var configuredScopes map[string]map[string]any
		if json.Unmarshal(scopesOutput, &configuredScopes) == nil {
			for scope, values := range configuredScopes {
				normalizedScope := strings.TrimPrefix(strings.ToLower(scope), "@")
				scopes[normalizedScope] = values
				registryValue, _ := values["npmRegistryServer"].(string)
				if registryValue == "" {
					continue
				}
				parsed, parseErr := shared.ParseURL("npmScopes."+scope, registryValue)
				if parseErr != nil {
					return nil, nil, nil, parseErr
				}
				named["@"+normalizedScope] = parsed
			}
		}
	}
	return registry, named, scopes, nil
}

func parseClassic(output []byte) (*url.URL, map[string]*url.URL, error) {
	values, err := parseClassicValues(output)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, nil, fmt.Errorf("encode Yarn configuration: %w", err)
	}
	return shared.ParseNPMJSON(data)
}

func parseClassicValues(output []byte) (map[string]json.RawMessage, error) {
	values := make(map[string]json.RawMessage)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		var event struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.Type != "inspect" || len(event.Data) == 0 {
			continue
		}
		var inspected map[string]json.RawMessage
		if json.Unmarshal(event.Data, &inspected) == nil {
			for key, value := range inspected {
				values[key] = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func (manager *Manager) Prepare(_ string, args []string, registryURL string, named map[string]string) (proxy.PreparedCommand, error) {
	if !manager.modern {
		options := []string{"--registry=" + registryURL, "--pure-lockfile"}
		options = append(options, shared.SortedNamedOptions(named, func(name, value string) string {
			return "--" + name + ":registry=" + value
		})...)
		return proxy.PreparedCommand{Args: shared.InsertOptions(args, options)}, nil
	}
	scopes := make(map[string]map[string]any, len(named))
	for scope, registry := range named {
		name := strings.TrimPrefix(scope, "@")
		values := make(map[string]any)
		for key, value := range manager.modernScopes[name] {
			values[key] = value
		}
		values["npmRegistryServer"] = registry
		scopes[name] = values
	}
	encodedScopes, err := json.Marshal(scopes)
	if err != nil {
		return proxy.PreparedCommand{}, fmt.Errorf("encode Yarn scopes: %w", err)
	}
	return proxy.PreparedCommand{
		Args: shared.InsertOptions(args, []string{"--immutable"}),
		Env: shared.OverrideEnvironment(map[string]string{
			"YARN_NPM_REGISTRY_SERVER": registryURL,
			"YARN_NPM_SCOPES":          string(encodedScopes),
		}),
	}, nil
}
