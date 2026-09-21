// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"gopkg.in/yaml.v3"
)

func TestParseClassic(t *testing.T) {
	registry, named, err := parseClassic([]byte(
		"{\"type\":\"info\",\"data\":\"yarn config\"}\n" +
			"{\"type\":\"inspect\",\"data\":{\"registry\":\"https://registry.example\"}}\n" +
			"{\"type\":\"inspect\",\"data\":{\"@private:registry\":\"https://private.example\"}}\n",
	))
	if err != nil {
		t.Fatalf("parseClassic() error = %v", err)
	}
	if got := registry.String(); got != "https://registry.example/" {
		t.Errorf("registry = %q", got)
	}
	if got := named["@private"].String(); got != "https://private.example/" {
		t.Errorf("scope = %q", got)
	}
}

func TestPrepareModernUsesTemporaryRCWithoutAuthentication(t *testing.T) {
	workingDirectory := changeWorkingDirectory(t)
	if err := os.WriteFile(filepath.Join(workingDirectory, ".yarnrc.yml"), []byte(`
nodeLinker: node-modules
npmAuthToken: default-secret
npmRegistries:
  //registry.example:
    npmAuthToken: registry-secret
`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		modern: true,
		modernScopes: map[string]map[string]any{
			"private": {"npmAuthToken": "secret", "npmAlwaysAuth": true},
		},
	}
	prepared, err := manager.Prepare("yarn", []string{"install"}, "http://proxy/default/", map[string]string{"@private": "http://proxy/private/"})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() { _ = prepared.Cleanup() })
	environment := strings.Join(prepared.Env, "\n")
	if strings.Contains(environment, "YARN_NPM_SCOPES=") {
		t.Fatalf("environment contains unsupported YARN_NPM_SCOPES: %s", environment)
	}
	rcFilename := environmentValue(prepared.Env, "YARN_RC_FILENAME")
	contents, err := os.ReadFile(filepath.Join(workingDirectory, rcFilename))
	if err != nil {
		t.Fatalf("read temporary Yarn configuration: %v", err)
	}
	var configuration map[string]any
	if err := yaml.Unmarshal(contents, &configuration); err != nil {
		t.Fatalf("parse temporary Yarn configuration: %v", err)
	}
	if configuration["nodeLinker"] != "node-modules" {
		t.Errorf("nodeLinker = %v, want preserved project setting", configuration["nodeLinker"])
	}
	if configuration["npmRegistryServer"] != "http://proxy/default/" {
		t.Errorf("npmRegistryServer = %v", configuration["npmRegistryServer"])
	}
	scopes, ok := configuration["npmScopes"].(map[string]any)
	if !ok {
		t.Fatalf("npmScopes = %#v", configuration["npmScopes"])
	}
	private, ok := scopes["private"].(map[string]any)
	if !ok {
		t.Fatalf("npmScopes.private = %#v", scopes["private"])
	}
	if private["npmAlwaysAuth"] != true {
		t.Errorf("scope settings were not preserved: %#v", private)
	}
	if private["npmRegistryServer"] != "http://proxy/private/" {
		t.Errorf("scope registry = %v", private["npmRegistryServer"])
	}
	if _, found := private["npmAuthToken"]; found {
		t.Errorf("temporary scope contains authentication: %#v", private)
	}
	if strings.Contains(string(contents), "secret") {
		t.Errorf("temporary configuration contains authentication: %s", contents)
	}
}

func TestPrepareModernPreservesLayeredConfiguration(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "project", "packages", "app")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.WriteFile(filepath.Join(root, ".yarnrc.yml"), []byte("cacheFolder: .cache\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte("nodeLinker: node-modules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changeWorkingDirectoryTo(t, child)

	manager := &Manager{modern: true, modernScopes: map[string]map[string]any{}}
	prepared, err := manager.Prepare("yarn", []string{"install"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	rcFilename := environmentValue(prepared.Env, "YARN_RC_FILENAME")
	for _, directory := range []string{child, project, root} {
		if _, err := os.Stat(filepath.Join(directory, rcFilename)); err != nil {
			t.Errorf("temporary configuration in %s: %v", directory, err)
		}
	}
	parentConfiguration, err := readModernRC(filepath.Join(root, rcFilename))
	if err != nil {
		t.Fatal(err)
	}
	if parentConfiguration["cacheFolder"] != ".cache" {
		t.Errorf("parent cacheFolder = %v", parentConfiguration["cacheFolder"])
	}
	projectConfiguration, err := readModernRC(filepath.Join(project, rcFilename))
	if err != nil {
		t.Fatal(err)
	}
	if projectConfiguration["nodeLinker"] != "node-modules" {
		t.Errorf("project nodeLinker = %v", projectConfiguration["nodeLinker"])
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	for _, directory := range []string{child, project, root} {
		if _, err := os.Stat(filepath.Join(directory, rcFilename)); !os.IsNotExist(err) {
			t.Errorf("temporary configuration still exists in %s: %v", directory, err)
		}
	}
}

func TestModernRegistryCredential(t *testing.T) {
	credential, ok := modernCredential(map[string]any{"npmAuthToken": "secret"})
	if !ok || credential.BearerToken != "secret" {
		t.Fatalf("token credential = %#v, %v", credential, ok)
	}
	credential, ok = modernCredential(map[string]any{"npmAuthIdent": "user:password"})
	if !ok || credential.Username != "user" || credential.Password != "password" {
		t.Fatalf("basic credential = %#v, %v", credential, ok)
	}
	registry, err := parseModernRegistry("//registry.example/packages/")
	if err != nil {
		t.Fatalf("parseModernRegistry() error = %v", err)
	}
	if registry.String() != "https://registry.example/packages/" {
		t.Errorf("registry = %q", registry)
	}
	credentials := make(map[string]proxy.RegistryCredential)
	if err := addModernRegistryCredentials(credentials, map[string]map[string]any{
		"//registry.example/packages/": {"npmAuthToken": "registry-secret"},
	}); err != nil {
		t.Fatalf("addModernRegistryCredentials() error = %v", err)
	}
	if credentials["https://registry.example/packages/"].BearerToken != "registry-secret" {
		t.Errorf("credentials = %#v", credentials)
	}
}

func TestDecodeModernMapRejectsMalformedConfiguration(t *testing.T) {
	_, err := decodeModernMap("npmScopes", []byte(`"not-an-object"`))
	if err == nil {
		t.Fatal("decodeModernMap() error = nil")
	}
	var configurationErr *modernConfigurationError
	if !errors.As(err, &configurationErr) {
		t.Fatalf("decodeModernMap() error = %T, want modernConfigurationError", err)
	}
}

func TestPrepareModernDoesNotForceImmutableOnUnrelatedCommand(t *testing.T) {
	changeWorkingDirectory(t)
	manager := &Manager{modern: true, modernScopes: map[string]map[string]any{}}
	prepared, err := manager.Prepare("yarn", []string{"npm", "whoami"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() { _ = prepared.Cleanup() })
	if strings.Contains(strings.Join(prepared.Args, " "), "--immutable") {
		t.Errorf("args = %v, should not force immutable mode", prepared.Args)
	}
}

func TestPrepareModernDoesNotForceImmutableForVersionFlag(t *testing.T) {
	changeWorkingDirectory(t)
	manager := &Manager{modern: true, modernScopes: map[string]map[string]any{}}
	prepared, err := manager.Prepare("yarn", []string{"--version"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() { _ = prepared.Cleanup() })
	if strings.Contains(strings.Join(prepared.Args, " "), "--immutable") {
		t.Errorf("args = %v, should not force immutable mode", prepared.Args)
	}
}

func TestPrepareClassicFreezesInstallAfterValueOption(t *testing.T) {
	manager := &Manager{}
	prepared, err := manager.Prepare("yarn", []string{"--cache-folder", "/tmp/cache", "install"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !strings.Contains(strings.Join(prepared.Args, " "), "--pure-lockfile") {
		t.Errorf("args = %v, want pure lockfile mode", prepared.Args)
	}
}

func TestPrepareModernFreezesNestedWorkspaceInstall(t *testing.T) {
	changeWorkingDirectory(t)
	manager := &Manager{modern: true, modernScopes: map[string]map[string]any{}}
	prepared, err := manager.Prepare("yarn", []string{"workspace", "web", "install"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() { _ = prepared.Cleanup() })
	if !strings.Contains(strings.Join(prepared.Args, " "), "--immutable") {
		t.Errorf("args = %v, want immutable mode", prepared.Args)
	}
}

func TestPrepareModernCleanupRemovesTemporaryConfiguration(t *testing.T) {
	workingDirectory := changeWorkingDirectory(t)
	manager := &Manager{modern: true, modernScopes: map[string]map[string]any{}}
	prepared, err := manager.Prepare("yarn", []string{"install"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	path := filepath.Join(workingDirectory, environmentValue(prepared.Env, "YARN_RC_FILENAME"))
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary configuration still exists: %v", err)
	}
}

func changeWorkingDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	changeWorkingDirectoryTo(t, directory)
	return directory
}

func changeWorkingDirectoryTo(t *testing.T, directory string) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
}

func environmentValue(environment []string, name string) string {
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	return ""
}
