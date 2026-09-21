// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	proxyecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem"
)

const defaultNPMRegistry = "https://registry.npmjs.org/"

// NPMConfig contains the effective npm registry configuration needed to route
// requests received by the local proxy.
type NPMConfig struct {
	Registry         *url.URL
	ScopedRegistries map[string]*url.URL
	// ResponseHandler implements the registry protocol. A nil handler selects
	// npm for backwards compatibility.
	ResponseHandler proxyecosystem.Handler
	// AllowUnauthenticatedLocalRequests is intended for managers that cannot
	// attach a private bearer token without exposing it in argv or the
	// environment. Registry routes still contain an unguessable capability.
	AllowUnauthenticatedLocalRequests bool
	// ForwardAuthorization preserves credentials supplied by a manager for a
	// named repository. Routes are unguessable and bound to one upstream.
	ForwardAuthorization         bool
	credentials                  map[string]npmCredentials
	basicCredentials             map[string]basicCredential
	configFiles                  []string
	userConfigFile               string
	supportsSafeLockfileOmission bool
	insecureSkipTLSVerify        bool
	caCertificates               []string
	caFile                       string
	httpProxy                    string
	httpsProxy                   string
	noProxy                      []string
	clientCertificate            string
	clientKey                    string
	scriptShell                  string
	global                       bool
	location                     string
	projectDirectory             string
	lockfileDestinations         map[string]*url.URL
}

type npmCredentials struct {
	token           string
	auth            string
	username        string
	password        string
	certificateFile string
	keyFile         string
}

type basicCredential struct {
	username string
	password string
}

// LoadNPMConfig asks npm for its effective configuration. npm has already
// applied global, user, project, and environment precedence when it emits JSON.
func LoadNPMConfig(ctx context.Context, executable string) (NPMConfig, error) {
	command := exec.CommandContext(ctx, executable, "config", "list", "--json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return NPMConfig{}, fmt.Errorf("dump npm configuration: %w: %s", err, detail)
		}
		return NPMConfig{}, fmt.Errorf("dump npm configuration: %w", err)
	}

	return LoadNPMConfigData(ctx, executable, stdout.Bytes())
}

// LoadNPMConfigData completes npm configuration discovery from the JSON
// fetched by the npm manager adapter.
func LoadNPMConfigData(ctx context.Context, executable string, data []byte) (NPMConfig, error) {
	config, err := parseNPMConfig(data)
	if err != nil {
		return NPMConfig{}, fmt.Errorf("dump npm configuration: %w", err)
	}
	majorVersion, err := npmMajorVersion(ctx, executable)
	if err != nil {
		return NPMConfig{}, fmt.Errorf("dump npm version: %w", err)
	}
	config.supportsSafeLockfileOmission = majorVersion >= 8

	config.projectDirectory = npmProjectDirectory(ctx, executable)
	if config.projectDirectory != "" {
		config.configFiles = append(config.configFiles, filepath.Join(config.projectDirectory, ".npmrc"))
	}
	credentials, err := loadNPMCredentials(config.configFiles, os.Environ())
	if err != nil {
		return NPMConfig{}, fmt.Errorf("dump npm authentication configuration: %w", err)
	}
	config.credentials = credentials
	lockfileDestinations, err := loadLockfileDestinations(config.projectDirectory)
	if err != nil {
		return NPMConfig{}, fmt.Errorf("dump npm lockfile destinations: %w", err)
	}
	config.lockfileDestinations = lockfileDestinations
	return config, nil
}

func parseNPMConfig(data []byte) (NPMConfig, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return NPMConfig{}, fmt.Errorf("decode JSON: %w", err)
	}

	registryValue := defaultNPMRegistry
	if raw, ok := values["registry"]; ok {
		if err := json.Unmarshal(raw, &registryValue); err != nil {
			return NPMConfig{}, fmt.Errorf("decode registry: %w", err)
		}
	}
	registry, err := parseRegistryURL("registry", registryValue)
	if err != nil {
		return NPMConfig{}, err
	}

	config := NPMConfig{
		Registry:             registry,
		ScopedRegistries:     make(map[string]*url.URL),
		credentials:          make(map[string]npmCredentials),
		lockfileDestinations: make(map[string]*url.URL),
	}
	if raw := values["global"]; raw != nil && string(raw) != "null" {
		if err := json.Unmarshal(raw, &config.global); err != nil {
			return NPMConfig{}, fmt.Errorf("decode global: %w", err)
		}
	}
	if raw := values["location"]; raw != nil && string(raw) != "null" {
		if err := json.Unmarshal(raw, &config.location); err != nil {
			return NPMConfig{}, fmt.Errorf("decode location: %w", err)
		}
		config.location = strings.ToLower(config.location)
	}
	if raw := values["strict-ssl"]; raw != nil && string(raw) != "null" {
		var strictSSL bool
		if err := json.Unmarshal(raw, &strictSSL); err != nil {
			return NPMConfig{}, fmt.Errorf("decode strict-ssl: %w", err)
		}
		config.insecureSkipTLSVerify = !strictSSL
	}
	for key, destination := range map[string]*string{
		"cafile":       &config.caFile,
		"proxy":        &config.httpProxy,
		"https-proxy":  &config.httpsProxy,
		"cert":         &config.clientCertificate,
		"key":          &config.clientKey,
		"script-shell": &config.scriptShell,
	} {
		if raw := values[key]; raw != nil && string(raw) != "null" {
			value, err := npmConfigOptionalString(raw)
			if err != nil {
				return NPMConfig{}, fmt.Errorf("decode %s: %w", key, err)
			}
			*destination = value
		}
	}
	caCertificates, err := npmConfigStrings(values["ca"])
	if err != nil {
		return NPMConfig{}, fmt.Errorf("decode ca: %w", err)
	}
	config.caCertificates = caCertificates
	noProxy, err := npmConfigStrings(values["noproxy"])
	if err != nil {
		return NPMConfig{}, fmt.Errorf("decode noproxy: %w", err)
	}
	config.noProxy = noProxy
	for _, key := range []string{"globalconfig", "userconfig"} {
		var path string
		if raw, ok := values[key]; ok && json.Unmarshal(raw, &path) == nil && path != "" {
			config.configFiles = append(config.configFiles, path)
			if key == "userconfig" {
				config.userConfigFile = path
			}
		}
	}
	for key, raw := range values {
		if !strings.HasPrefix(key, "@") || !strings.HasSuffix(key, ":registry") {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return NPMConfig{}, fmt.Errorf("decode %s: %w", key, err)
		}
		scope := strings.ToLower(strings.TrimSuffix(key, ":registry"))
		if scope == "@" {
			return NPMConfig{}, fmt.Errorf("invalid npm registry scope %q", key)
		}
		registry, err := parseRegistryURL(key, value)
		if err != nil {
			return NPMConfig{}, err
		}
		config.ScopedRegistries[scope] = registry
	}
	return config, nil
}

func npmConfigStrings(raw json.RawMessage) ([]string, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return nonEmptyStrings(values), nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return nonEmptyStrings([]string{value}), nil
}

func npmConfigOptionalString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	var enabled bool
	if err := json.Unmarshal(raw, &enabled); err == nil && !enabled {
		return "", nil
	}
	return "", fmt.Errorf("expected a string or false")
}

func nonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	return result
}

func parseRegistryURL(name, value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid npm %s URL", name)
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed, nil
}

func npmMajorVersion(ctx context.Context, executable string) (int, error) {
	output, err := exec.CommandContext(ctx, executable, "--version").Output()
	if err != nil {
		return 0, err
	}
	major, _, _ := strings.Cut(strings.TrimSpace(string(output)), ".")
	value, err := strconv.Atoi(major)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", strings.TrimSpace(string(output)), err)
	}
	return value, nil
}

func npmProjectDirectory(ctx context.Context, executable string) string {
	output, err := exec.CommandContext(ctx, executable, "prefix").Output()
	if err == nil && strings.TrimSpace(string(output)) != "" {
		return strings.TrimSpace(string(output))
	}
	directory, _ := os.Getwd()
	return directory
}

func loadNPMCredentials(files, environment []string) (map[string]npmCredentials, error) {
	values := make(map[string]string)
	for _, path := range files {
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if err := readNPMRC(file, values); err != nil {
			return nil, errors.Join(fmt.Errorf("read %s: %w", path, err), file.Close())
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close %s: %w", path, err)
		}
	}
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		if !ok || !strings.HasPrefix(strings.ToLower(name), "npm_config_") {
			continue
		}
		key := name[len("npm_config_"):]
		if strings.HasPrefix(key, "//") {
			values[key] = value
		}
	}

	credentials := make(map[string]npmCredentials)
	for key, value := range values {
		separator := strings.LastIndex(key, ":")
		if separator < 0 {
			continue
		}
		prefix, field := key[:separator], key[separator+1:]
		if !strings.HasPrefix(prefix, "//") {
			continue
		}
		prefix = normalizeCredentialPrefix(prefix)
		credential := credentials[prefix]
		recognized := true
		switch strings.ToLower(field) {
		case "_authtoken":
			credential.token = value
		case "_auth":
			credential.auth = value
		case "username":
			credential.username = value
		case "_password":
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				credential.password = string(decoded)
			}
		case "certfile":
			credential.certificateFile = value
		case "keyfile":
			credential.keyFile = value
		default:
			recognized = false
		}
		if recognized {
			credentials[prefix] = credential
		}
	}
	for prefix, credential := range credentials {
		usableAuth := credential.token != "" || credential.auth != "" || (credential.username != "" && credential.password != "")
		usableCertificate := credential.certificateFile != "" && credential.keyFile != ""
		if !usableAuth && !usableCertificate {
			delete(credentials, prefix)
		}
	}
	return credentials, nil
}

func readNPMRC(reader io.Reader, values map[string]string) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = os.ExpandEnv(strings.TrimSpace(value))
	}
	return scanner.Err()
}

func normalizeCredentialPrefix(prefix string) string {
	remainder := strings.TrimPrefix(strings.TrimSpace(prefix), "//")
	authority, path, hasPath := strings.Cut(remainder, "/")
	normalized := "//" + strings.ToLower(authority)
	if hasPath {
		normalized += "/" + path
	} else {
		normalized += "/"
	}
	return normalized
}

func (config NPMConfig) credentialsFor(destination *url.URL) (string, npmCredentials, bool) {
	requestKey := "//" + strings.ToLower(destination.Host) + destination.EscapedPath()
	var selected string
	var credential npmCredentials
	for prefix, candidate := range config.credentials {
		matches := strings.HasPrefix(requestKey, prefix)
		if !strings.HasSuffix(prefix, "/") {
			matches = requestKey == prefix || strings.HasPrefix(requestKey, prefix+"/")
		}
		if matches && len(prefix) > len(selected) {
			selected = prefix
			credential = candidate
		}
	}
	return selected, credential, selected != ""
}

func (config NPMConfig) authorize(request *http.Request) {
	_, credential, ok := config.credentialsFor(request.URL)
	if !ok {
		if request.URL.User != nil {
			password, _ := request.URL.User.Password()
			request.SetBasicAuth(request.URL.User.Username(), password)
		} else if credential, exists := config.basicCredentials[strings.ToLower(request.URL.Hostname())]; exists {
			request.SetBasicAuth(credential.username, credential.password)
		}
		return
	}
	switch {
	case credential.token != "":
		request.Header.Set("Authorization", "Bearer "+credential.token)
	case credential.auth != "":
		request.Header.Set("Authorization", "Basic "+credential.auth)
	case credential.username != "" && credential.password != "":
		request.SetBasicAuth(credential.username, credential.password)
	}
}

func loadLockfileDestinations(directory string) (map[string]*url.URL, error) {
	destinations := make(map[string]*url.URL)
	if directory == "" {
		return destinations, nil
	}
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		contents, err := os.ReadFile(filepath.Join(directory, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var document any
		if err := json.Unmarshal(contents, &document); err != nil {
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}
		if err := collectLockfileDestinations(document, destinations); err != nil {
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}
		break
	}
	return destinations, nil
}

func collectLockfileDestinations(value any, destinations map[string]*url.URL) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "resolved" {
				resolved, ok := child.(string)
				if !ok {
					continue
				}
				destination, err := url.Parse(resolved)
				if err != nil || (destination.Scheme != "http" && destination.Scheme != "https") || destination.Host == "" {
					continue
				}
				destinationKey := lockfileDestinationKey(destination)
				if existing := destinations[destinationKey]; existing != nil && existing.String() != destination.String() {
					return errors.New("ambiguous resolved URLs share a path and query")
				}
				destinations[destinationKey] = destination
				continue
			}
			if err := collectLockfileDestinations(child, destinations); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := collectLockfileDestinations(child, destinations); err != nil {
				return err
			}
		}
	}
	return nil
}

func lockfileDestinationKey(destination *url.URL) string {
	key := destination.EscapedPath()
	if key == "" {
		key = "/"
	}
	if destination.RawQuery != "" {
		key += "?" + destination.RawQuery
	}
	return key
}

func npmProxyOverrides(defaultRegistry string, scopedRegistries map[string]string) map[string]string {
	overrides := map[string]string{
		"npm_config_registry":                        defaultRegistry,
		"npm_config_omit_lockfile_registry_resolved": "true",
		"npm_config_replace_registry_host":           "always",
		"NPM_CONFIG_REGISTRY":                        defaultRegistry,
		"NPM_CONFIG_OMIT_LOCKFILE_REGISTRY_RESOLVED": "true",
		"NPM_CONFIG_REPLACE_REGISTRY_HOST":           "always",
	}
	for scope, registry := range scopedRegistries {
		overrides["npm_config_"+scope+":registry"] = registry
	}
	return overrides
}

func npmProxyEnvironment(environment []string, overrides map[string]string) []string {
	result := make([]string, 0, len(environment)+len(overrides))
	for _, item := range environment {
		name, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[name]; !replaced {
			result = append(result, item)
		}
	}
	for name, value := range overrides {
		result = append(result, name+"="+value)
	}
	return result
}
