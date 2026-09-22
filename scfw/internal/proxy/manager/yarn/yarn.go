// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package yarn owns Yarn Classic and modern Yarn registry configuration.
package yarn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	npmecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
	"gopkg.in/yaml.v3"
)

type Manager struct {
	modern           bool
	modernScopes     map[string]map[string]any
	modernUnsafeHTTP []string
}

func (Manager) Name() string { return "yarn" }

func (manager *Manager) Registries(ctx context.Context, executable string, _ []string) (proxy.RegistryConfiguration, error) {
	if registry, named, scopes, registries, err := loadModern(ctx, executable); err == nil {
		unsafeHTTP, unsafeHTTPErr := modernStrings(ctx, executable, "unsafeHttpWhitelist")
		if unsafeHTTPErr != nil {
			return proxy.RegistryConfiguration{}, newModernConfigurationError("read unsafeHttpWhitelist", unsafeHTTPErr)
		}
		manager.modern = true
		manager.modernScopes = scopes
		manager.modernUnsafeHTTP = unsafeHTTP
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
			if credential, ok := modernCredential(values); ok {
				configuration.Credentials[upstream.String()] = credential
			}
		}
		if err := addModernRegistryCredentials(configuration.Credentials, registries); err != nil {
			return proxy.RegistryConfiguration{}, err
		}
		configuration.CAFile, _ = modernString(ctx, executable, "httpsCaFilePath")
		configuration.ClientCertificateFile, _ = modernString(ctx, executable, "httpsCertFilePath")
		configuration.ClientKeyFile, _ = modernString(ctx, executable, "httpsKeyFilePath")
		if strictSSL, strictErr := modernBool(ctx, executable, "enableStrictSsl"); strictErr == nil {
			configuration.InsecureTLS = !strictSSL
		}
		return configuration, nil
	} else {
		var modernErr *modernConfigurationError
		if errors.As(err, &modernErr) {
			return proxy.RegistryConfiguration{}, err
		}
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

func modernStrings(ctx context.Context, executable, setting string) ([]string, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "get", setting, "--json")
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(output), []byte("undefined")) {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal(output, &values); err != nil {
		return nil, err
	}
	return values, nil
}

func loadModern(ctx context.Context, executable string) (*url.URL, map[string]*url.URL, map[string]map[string]any, map[string]map[string]any, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "get", "npmRegistryServer", "--json")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var registryValue string
	if err := json.Unmarshal(output, &registryValue); err != nil {
		return nil, nil, nil, nil, err
	}
	registry, err := shared.ParseURL("npmRegistryServer", registryValue)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	named := make(map[string]*url.URL)
	scopesOutput, err := shared.CommandOutput(ctx, executable, "config", "get", "npmScopes", "--json", "--no-redacted")
	if err != nil {
		return nil, nil, nil, nil, newModernConfigurationError("read npmScopes", err)
	}
	configuredScopes, err := decodeModernMap("npmScopes", scopesOutput)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	scopes := make(map[string]map[string]any, len(configuredScopes))
	for scope, values := range configuredScopes {
		normalizedScope := strings.TrimPrefix(strings.ToLower(scope), "@")
		scopes[normalizedScope] = values
		registryValue, _ := values["npmRegistryServer"].(string)
		if registryValue == "" {
			continue
		}
		parsed, parseErr := shared.ParseURL("npmScopes."+scope, registryValue)
		if parseErr != nil {
			return nil, nil, nil, nil, newModernConfigurationError("parse npmScopes", parseErr)
		}
		named["@"+normalizedScope] = parsed
	}
	registriesOutput, err := shared.CommandOutput(ctx, executable, "config", "get", "npmRegistries", "--json", "--no-redacted")
	if err != nil {
		return nil, nil, nil, nil, newModernConfigurationError("read npmRegistries", err)
	}
	registries, err := decodeModernMap("npmRegistries", registriesOutput)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return registry, named, scopes, registries, nil
}

type modernConfigurationError struct {
	operation string
	err       error
}

func (err *modernConfigurationError) Error() string {
	return fmt.Sprintf("%s: %v", err.operation, err.err)
}

func (err *modernConfigurationError) Unwrap() error { return err.err }

func newModernConfigurationError(operation string, err error) error {
	return &modernConfigurationError{operation: operation, err: err}
}

func decodeModernMap(name string, data []byte) (map[string]map[string]any, error) {
	values := make(map[string]map[string]any)
	if bytes.Equal(bytes.TrimSpace(data), []byte("undefined")) {
		return values, nil
	}
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, newModernConfigurationError("decode "+name, err)
	}
	if values == nil {
		values = make(map[string]map[string]any)
	}
	return values, nil
}

func modernCredential(values map[string]any) (proxy.RegistryCredential, bool) {
	if token, ok := values["npmAuthToken"].(string); ok && token != "" {
		return proxy.RegistryCredential{BearerToken: token}, true
	}
	if ident, ok := values["npmAuthIdent"].(string); ok {
		if username, password, found := strings.Cut(ident, ":"); found {
			return proxy.RegistryCredential{Username: username, Password: password}, true
		}
	}
	return proxy.RegistryCredential{}, false
}

func parseModernRegistry(value string) (*url.URL, error) {
	if strings.HasPrefix(value, "//") {
		value = "https:" + value
	}
	registry, err := shared.ParseURL("npmRegistries", value)
	if err != nil {
		return nil, fmt.Errorf("parse Yarn npmRegistries entry: %w", err)
	}
	return registry, nil
}

func addModernRegistryCredentials(credentials map[string]proxy.RegistryCredential, registries map[string]map[string]any) error {
	for registryName, values := range registries {
		credential, ok := modernCredential(values)
		if !ok {
			continue
		}
		upstream, err := parseModernRegistry(registryName)
		if err != nil {
			return err
		}
		credentials[upstream.String()] = credential
	}
	return nil
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
	positionals := shared.PositionalArguments(args, yarnOptionsWithValue)
	install := yarnInstallOperation(positionals, args)
	if !manager.modern {
		options := []string{"--registry=" + registryURL}
		if install {
			options = append(options, "--pure-lockfile")
		}
		options = append(options, shared.SortedNamedOptions(named, func(name, value string) string {
			return "--" + name + ":registry=" + value
		})...)
		return proxy.PreparedCommand{Args: shared.InsertOptions(args, options)}, nil
	}
	scopes := make(map[string]map[string]any, len(manager.modernScopes)+len(named))
	for scope, configuredValues := range manager.modernScopes {
		values := make(map[string]any, len(configuredValues))
		for key, value := range configuredValues {
			if isAuthenticationSetting(key) {
				continue
			}
			values[key] = value
		}
		scopes[scope] = values
	}
	for scope, registry := range named {
		name := strings.TrimPrefix(scope, "@")
		values := scopes[name]
		if values == nil {
			values = make(map[string]any)
			scopes[name] = values
		}
		values["npmRegistryServer"] = registry
	}
	unsafeHTTP := append([]string(nil), manager.modernUnsafeHTTP...)
	proxyURL, err := url.Parse(registryURL)
	if err != nil || proxyURL.Hostname() == "" {
		return proxy.PreparedCommand{}, fmt.Errorf("parse Yarn proxy URL %q", registryURL)
	}
	unsafeHTTP = appendUnique(unsafeHTTP, proxyURL.Hostname())
	rcFilename, cleanup, err := writeModernRC(registryURL, scopes, unsafeHTTP)
	if err != nil {
		return proxy.PreparedCommand{}, err
	}
	options := []string(nil)
	if install {
		options = append(options, "--immutable")
	}
	return proxy.PreparedCommand{
		Args: shared.InsertOptions(args, options),
		Env: shared.OverrideEnvironment(map[string]string{
			"YARN_RC_FILENAME": rcFilename,
		}, "YARN_NPM_REGISTRY_SERVER", "YARN_NPM_SCOPES"),
		Cleanup: cleanup,
	}, nil
}

func writeModernRC(registryURL string, scopes map[string]map[string]any, unsafeHTTP []string) (string, func() error, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", nil, fmt.Errorf("get working directory for Yarn configuration: %w", err)
	}

	sourceName := os.Getenv("YARN_RC_FILENAME")
	if sourceName == "" {
		sourceName = ".yarnrc.yml"
	}
	if filepath.Base(sourceName) != sourceName {
		return "", nil, fmt.Errorf("YARN_RC_FILENAME must be a filename, got %q", sourceName)
	}
	file, err := os.CreateTemp(cwd, ".scfw-yarnrc-*.yml")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary Yarn configuration: %w", err)
	}
	temporaryName := filepath.Base(file.Name())
	temporaryPaths := []string{file.Name()}
	cleanup := func() error {
		var cleanupErr error
		for _, path := range temporaryPaths {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
		return cleanupErr
	}
	sourcePaths := findRCs(cwd, sourceName)
	home, _ := os.UserHomeDir()
	var overlayConfiguration map[string]any
	for _, sourcePath := range sourcePaths {
		directory := filepath.Dir(sourcePath)
		if sourceName == ".yarnrc.yml" && samePath(directory, home) {
			continue
		}
		configuration, readErr := readModernRC(sourcePath)
		if readErr != nil {
			return "", nil, errors.Join(readErr, file.Close(), cleanup())
		}
		scrubAuthentication(configuration)
		if samePath(directory, cwd) {
			configuration["npmRegistryServer"] = registryURL
			configuration["npmScopes"] = scopes
			configuration["unsafeHttpWhitelist"] = unsafeHTTP
			overlayConfiguration = configuration
			continue
		}
		targetPath := filepath.Join(directory, temporaryName)
		if writeErr := writeModernRCFile(targetPath, configuration); writeErr != nil {
			return "", nil, errors.Join(writeErr, file.Close(), cleanup())
		}
		temporaryPaths = append(temporaryPaths, targetPath)
	}
	if overlayConfiguration == nil {
		overlayConfiguration = map[string]any{
			"npmRegistryServer":   registryURL,
			"npmScopes":           scopes,
			"unsafeHttpWhitelist": unsafeHTTP,
		}
	}
	contents, err := yaml.Marshal(overlayConfiguration)
	if err != nil {
		return "", nil, errors.Join(fmt.Errorf("encode Yarn configuration: %w", err), file.Close(), cleanup())
	}
	if _, err := file.Write(contents); err != nil {
		return "", nil, errors.Join(fmt.Errorf("write temporary Yarn configuration: %w", err), file.Close(), cleanup())
	}
	if err := file.Close(); err != nil {
		return "", nil, errors.Join(fmt.Errorf("close temporary Yarn configuration: %w", err), cleanup())
	}
	return temporaryName, cleanup, nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func findRCs(directory, name string) []string {
	var paths []string
	for {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return paths
		}
		directory = parent
	}
}

func readModernRC(path string) (map[string]any, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Yarn configuration %s: %w", path, err)
	}
	configuration := make(map[string]any)
	if err := yaml.Unmarshal(contents, &configuration); err != nil {
		return nil, fmt.Errorf("parse Yarn configuration %s: %w", path, err)
	}
	if configuration == nil {
		configuration = make(map[string]any)
	}
	return configuration, nil
}

func writeModernRCFile(path string, configuration map[string]any) error {
	contents, err := yaml.Marshal(configuration)
	if err != nil {
		return fmt.Errorf("encode Yarn configuration: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary Yarn configuration %s: %w", path, err)
	}
	if _, err := file.Write(contents); err != nil {
		return errors.Join(fmt.Errorf("write temporary Yarn configuration %s: %w", path, err), file.Close(), os.Remove(path))
	}
	if err := file.Close(); err != nil {
		return errors.Join(fmt.Errorf("close temporary Yarn configuration %s: %w", path, err), os.Remove(path))
	}
	return nil
}

func scrubAuthentication(configuration map[string]any) {
	delete(configuration, "npmAuthToken")
	delete(configuration, "npmAuthIdent")
	for _, setting := range []string{"npmScopes", "npmRegistries"} {
		values, ok := configuration[setting].(map[string]any)
		if !ok {
			continue
		}
		for _, rawEntry := range values {
			if entry, ok := rawEntry.(map[string]any); ok {
				delete(entry, "npmAuthToken")
				delete(entry, "npmAuthIdent")
			}
		}
	}
}

func isAuthenticationSetting(name string) bool {
	return name == "npmAuthToken" || name == "npmAuthIdent"
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	leftPath, leftErr := filepath.Abs(left)
	rightPath, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftPath == rightPath
}

var yarnOptionsWithValue = map[string]bool{
	"--cache-folder":           true,
	"--cwd":                    true,
	"--global-folder":          true,
	"--https-proxy":            true,
	"--modules-folder":         true,
	"--mutex":                  true,
	"--network-concurrency":    true,
	"--network-timeout":        true,
	"--preferred-cache-folder": true,
	"--proxy":                  true,
	"--registry":               true,
	"--use-yarnrc":             true,
}

func yarnInstallOperation(positionals, args []string) bool {
	if len(positionals) == 0 {
		return yarnDefaultsToInstall(args)
	}
	if positionals[0] == "install" {
		return true
	}
	return len(positionals) > 2 && positionals[0] == "workspace" && positionals[2] == "install"
}

func yarnDefaultsToInstall(args []string) bool {
	for _, argument := range args {
		switch strings.ToLower(argument) {
		case "--help", "-h", "--version", "-v":
			return false
		}
	}
	return true
}
