// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNPMConfig(t *testing.T) {
	config, err := parseNPMConfig([]byte(`{
		"registry":"https://registry.example.com/npm",
		"@private:registry":"https://private.example.com/packages/",
		"strict-ssl":false,
		"proxy":false,
		"https-proxy":false,
		"ca":["one","two"],
		"noproxy":[""],
		"global":true,
		"location":"project",
		"globalconfig":"/global/npmrc",
		"userconfig":"/user/npmrc"
	}`))
	if err != nil {
		t.Fatalf("parseNPMConfig() returned unexpected error: %v", err)
	}
	if got, want := config.Registry.String(), "https://registry.example.com/npm/"; got != want {
		t.Errorf("Registry = %q, want %q", got, want)
	}
	if got, want := config.ScopedRegistries["@private"].String(), "https://private.example.com/packages/"; got != want {
		t.Errorf("scoped registry = %q, want %q", got, want)
	}
	if !config.insecureSkipTLSVerify {
		t.Error("strict-ssl=false did not configure insecure transport compatibility")
	}
	if len(config.caCertificates) != 2 || len(config.noProxy) != 0 {
		t.Errorf("array/string npm config not decoded: ca=%v noproxy=%v", config.caCertificates, config.noProxy)
	}
	if config.httpProxy != "" || config.httpsProxy != "" {
		t.Errorf("boolean false proxy configuration was not treated as disabled: http=%q https=%q", config.httpProxy, config.httpsProxy)
	}
	if !config.global || config.location != "project" {
		t.Errorf("npm configuration mode not decoded: global=%t location=%q", config.global, config.location)
	}
	if got, want := config.configFiles, []string{"/global/npmrc", "/user/npmrc"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("configFiles = %v, want %v", got, want)
	}
}

func TestLoadNPMCredentialsHonorsFileAndEnvironmentPrecedence(t *testing.T) {
	directory := t.TempDir()
	npmrc := filepath.Join(directory, ".npmrc")
	contents := "//registry.example.com/:_authToken=file-token\n" +
		"//registry.example.com/private/:username=alice\n" +
		"//registry.example.com/private/:_password=c2VjcmV0\n" +
		"//registry.example.com:4873/:_authToken=port-token\n"
	if err := os.WriteFile(npmrc, []byte(contents), 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}
	credentials, err := loadNPMCredentials([]string{npmrc}, []string{"npm_config_//registry.example.com/:_authToken=env-token"})
	if err != nil {
		t.Fatalf("loadNPMCredentials() returned unexpected error: %v", err)
	}
	config := NPMConfig{credentials: credentials}

	publicRequest := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example.com/pkg")}
	config.authorize(publicRequest)
	if got, want := publicRequest.Header.Get("Authorization"), "Bearer env-token"; got != want {
		t.Errorf("public Authorization = %q, want %q", got, want)
	}
	privateRequest := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example.com/private/pkg")}
	config.authorize(privateRequest)
	if got, want := privateRequest.Header.Get("Authorization"), "Basic YWxpY2U6c2VjcmV0"; got != want {
		t.Errorf("private Authorization = %q, want %q", got, want)
	}
	portRequest := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example.com:4873/pkg")}
	config.authorize(portRequest)
	if got, want := portRequest.Header.Get("Authorization"), "Bearer port-token"; got != want {
		t.Errorf("port Authorization = %q, want %q", got, want)
	}
}

func TestCredentialPathMatchingPreservesCase(t *testing.T) {
	config := NPMConfig{credentials: map[string]npmCredentials{
		normalizeCredentialPrefix("//Registry.Example/Private/"): {token: "private-token"},
	}}
	matching := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://REGISTRY.EXAMPLE/Private/pkg")}
	config.authorize(matching)
	if got := matching.Header.Get("Authorization"); got != "Bearer private-token" {
		t.Errorf("matching path Authorization = %q", got)
	}
	caseVariant := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example/private/pkg")}
	config.authorize(caseVariant)
	if got := caseVariant.Header.Get("Authorization"); got != "" {
		t.Errorf("case-variant path received scoped Authorization %q", got)
	}
}

func TestCredentialLookupFallsBackFromIncompleteScopedEntries(t *testing.T) {
	directory := t.TempDir()
	npmrc := filepath.Join(directory, ".npmrc")
	contents := "//registry.example/:_authToken=root-token\n" +
		"//registry.example/private/:username=alice\n" +
		"//registry.example/private/:_password=\n" +
		"//registry.example/empty-user/:username=\n" +
		"//registry.example/empty-user/:_password=c2VjcmV0\n" +
		"//registry.example/metadata/:always-auth=true\n"
	if err := os.WriteFile(npmrc, []byte(contents), 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}
	credentials, err := loadNPMCredentials([]string{npmrc}, nil)
	if err != nil {
		t.Fatalf("loadNPMCredentials() returned unexpected error: %v", err)
	}
	config := NPMConfig{credentials: credentials}
	for _, path := range []string{"/private/pkg", "/empty-user/pkg", "/metadata/pkg"} {
		request := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example"+path)}
		config.authorize(request)
		if got, want := request.Header.Get("Authorization"), "Bearer root-token"; got != want {
			t.Errorf("%s Authorization = %q, want root fallback %q", path, got, want)
		}
	}
}

func TestScopedTransportIgnoresIncompleteCertificateWhenTokenIsUsable(t *testing.T) {
	directory := t.TempDir()
	npmrc := filepath.Join(directory, ".npmrc")
	contents := "//registry.example/:_authToken=root-token\n" +
		"//registry.example/:certfile=/missing-client.pem\n"
	if err := os.WriteFile(npmrc, []byte(contents), 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}
	credentials, err := loadNPMCredentials([]string{npmrc}, nil)
	if err != nil {
		t.Fatalf("loadNPMCredentials() returned unexpected error: %v", err)
	}
	config := NPMConfig{credentials: credentials}
	base, err := config.transport()
	if err != nil {
		t.Fatalf("transport() returned unexpected error: %v", err)
	}
	transports, err := config.scopedTransports(base)
	if err != nil {
		t.Fatalf("scopedTransports() rejected incomplete optional mTLS pair: %v", err)
	}
	if len(transports) != 0 {
		t.Errorf("scopedTransports() = %v, want incomplete mTLS pair ignored", transports)
	}
	request := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example/pkg")}
	config.authorize(request)
	if got, want := request.Header.Get("Authorization"), "Bearer root-token"; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestCredentialPrefixWithoutTrailingSlashMatchesExactPathAndDescendants(t *testing.T) {
	directory := t.TempDir()
	npmrc := filepath.Join(directory, ".npmrc")
	if err := os.WriteFile(npmrc, []byte("//registry.example/path:_authToken=path-token\n"), 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}
	credentials, err := loadNPMCredentials([]string{npmrc}, nil)
	if err != nil {
		t.Fatalf("loadNPMCredentials() returned unexpected error: %v", err)
	}
	config := NPMConfig{credentials: credentials}
	for _, path := range []string{"/path", "/path/package"} {
		request := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example"+path)}
		config.authorize(request)
		if got, want := request.Header.Get("Authorization"), "Bearer path-token"; got != want {
			t.Errorf("%s Authorization = %q, want %q", path, got, want)
		}
	}
	unrelated := &http.Request{Header: make(http.Header), URL: mustParseURL(t, "https://registry.example/pathology")}
	config.authorize(unrelated)
	if got := unrelated.Header.Get("Authorization"); got != "" {
		t.Errorf("unrelated path received Authorization %q", got)
	}
}

func TestTransportFallsBackToEnvironmentNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")
	t.Setenv("NO_PROXY", "internal.example")
	config := NPMConfig{httpProxy: "http://proxy.example:8080"}
	transport, err := config.transport()
	if err != nil {
		t.Fatalf("transport() returned unexpected error: %v", err)
	}
	request := &http.Request{URL: mustParseURL(t, "https://internal.example/pkg")}
	proxyURL, err := transport.Proxy(request)
	if err != nil {
		t.Fatalf("Proxy() returned unexpected error: %v", err)
	}
	if proxyURL != nil {
		t.Errorf("Proxy() = %v, want direct connection from environment NO_PROXY", proxyURL)
	}
}

func TestRunNPMUsesProcessLocalConfigurationAndLeavesNPMRCUntouched(t *testing.T) {
	directory := t.TempDir()
	npmrcPath := filepath.Join(directory, ".npmrc")
	originalNPMRC := []byte("registry=https://registry.example.com/\n@private:registry=https://private.example.com/\n")
	if err := os.WriteFile(npmrcPath, originalNPMRC, 0o600); err != nil {
		t.Fatalf("write npmrc fixture: %v", err)
	}
	environmentPath := filepath.Join(directory, "child.env")
	argumentsPath := filepath.Join(directory, "child.args")
	authConfigPath := filepath.Join(directory, "auth-config")
	executablePath := filepath.Join(directory, "npm")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '11.0.0\n'
  exit 0
fi
if [ "$1" = "config" ]; then
  printf '{"registry":"https://registry.example.com/","@private:registry":"https://private.example.com/","userconfig":"%s","omit-lockfile-registry-resolved":false}\n'
  exit 0
fi
if [ "$1" = "prefix" ]; then
  printf '%%s\n' "$SCFW_PROXY_TEST_PREFIX"
  exit 0
fi
for argument in "$@"; do
  case "$argument" in
    --userconfig=*) cat "${argument#--userconfig=}" > "$SCFW_PROXY_TEST_AUTH" ;;
  esac
done
env > "$SCFW_PROXY_TEST_ENV"
printf '%%s\n' "$@" > "$SCFW_PROXY_TEST_ARGS"
printf 'npm child output\n'
`
	if err := os.WriteFile(executablePath, []byte(fmt.Sprintf(script, npmrcPath)), 0o700); err != nil {
		t.Fatalf("write npm fixture: %v", err)
	}
	t.Setenv("SCFW_PROXY_TEST_ENV", environmentPath)
	t.Setenv("SCFW_PROXY_TEST_ARGS", argumentsPath)
	t.Setenv("SCFW_PROXY_TEST_AUTH", authConfigPath)
	t.Setenv("SCFW_PROXY_TEST_PREFIX", directory)

	var stdout bytes.Buffer
	if err := RunNPM(context.Background(), executablePath, []string{"install", "pkg"}, Streams{Stdout: &stdout}, Options{}); err != nil {
		t.Fatalf("RunNPM() returned unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "npm child output") {
		t.Errorf("stdout = %q, want child output", stdout.String())
	}

	childEnvironment, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatalf("read child environment: %v", err)
	}
	for _, want := range []string{
		"npm_config_registry=http://127.0.0.1:",
		"npm_config_@private:registry=http://127.0.0.1:",
		"npm_config_omit_lockfile_registry_resolved=true",
		"npm_config_replace_registry_host=always",
	} {
		if !bytes.Contains(childEnvironment, []byte(want)) {
			t.Errorf("child environment does not contain %q", want)
		}
	}
	childArguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatalf("read child arguments: %v", err)
	}
	for _, want := range []string{"--registry=http://127.0.0.1:", "--userconfig=/dev/fd/3", "--script-shell=", "--omit-lockfile-registry-resolved=true", "--replace-registry-host=always"} {
		if !bytes.Contains(childArguments, []byte(want)) {
			t.Errorf("child arguments do not contain %q: %s", want, childArguments)
		}
	}
	authConfig, err := os.ReadFile(authConfigPath)
	if err != nil {
		t.Fatalf("read streamed npm authentication config: %v", err)
	}
	if !bytes.Contains(authConfig, originalNPMRC) || !bytes.Contains(authConfig, []byte("//127.0.0.1:")) || !bytes.Contains(authConfig, []byte(":_authToken=")) {
		t.Errorf("streamed npm authentication config does not preserve user config and add loopback auth: %s", authConfig)
	}
	lastLine := strings.TrimSpace(string(authConfig))
	lastLine = lastLine[strings.LastIndex(lastLine, "\n")+1:]
	_, localSecret, ok := strings.Cut(lastLine, "=")
	if !ok || localSecret == "" {
		t.Fatalf("could not extract local proxy secret from %q", lastLine)
	}
	if bytes.Contains(childArguments, []byte(localSecret)) || bytes.Contains(childEnvironment, []byte(localSecret)) {
		t.Error("local proxy secret leaked into child arguments or environment")
	}
	for _, argument := range strings.Split(string(childArguments), "\n") {
		if path, found := strings.CutPrefix(argument, "--userconfig="); found {
			if path != inheritedNPMConfigPath {
				t.Errorf("npm authentication config path = %q, want inherited descriptor %q", path, inheritedNPMConfigPath)
			}
		}
	}
	afterNPMRC, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatalf("read npmrc after RunNPM: %v", err)
	}
	if !bytes.Equal(afterNPMRC, originalNPMRC) {
		t.Errorf("npmrc changed: got %q, want %q", afterNPMRC, originalNPMRC)
	}
}

func TestValidateNPMConfigModeRejectsGlobalAndProjectLocations(t *testing.T) {
	for _, config := range []NPMConfig{
		{global: true, location: "user"},
		{location: "global"},
		{location: "project"},
	} {
		if err := validateNPMConfigMode(config); err == nil {
			t.Errorf("validateNPMConfigMode(%+v) = nil, want unsupported-mode error", config)
		}
	}
	if err := validateNPMConfigMode(NPMConfig{location: "user"}); err != nil {
		t.Errorf("validateNPMConfigMode(user) returned unexpected error: %v", err)
	}
}

func TestNPMAuthConfigIsProtectedAndReadOnly(t *testing.T) {
	authConfig, err := newNPMAuthConfig("", "//127.0.0.1:1234/:_authToken=secret\n")
	if err != nil {
		t.Fatalf("newNPMAuthConfig() returned unexpected error: %v", err)
	}
	defer func() {
		if err := authConfig.Close(); err != nil {
			t.Errorf("authConfig.Close(): %v", err)
		}
	}()
	if _, err := authConfig.file.Write([]byte("registry=https://changed.example/\n")); err == nil {
		t.Fatal("write to protected authentication config descriptor succeeded")
	}
	contents, err := io.ReadAll(authConfig.file)
	if err != nil {
		t.Fatalf("read authentication config: %v", err)
	}
	if got, want := string(contents), "//127.0.0.1:1234/:_authToken=secret\n"; got != want {
		t.Errorf("authentication config = %q, want %q", got, want)
	}
}

func TestNPMScriptShellRestoresOriginalEnvironment(t *testing.T) {
	originalRegistry := "https://user:pass@original.example/?signature=secret"
	wrapper, err := newNPMScriptShell("/bin/sh", []string{
		"PATH=" + os.Getenv("PATH"),
		"npm_config_registry=" + originalRegistry,
		"npm_config_userconfig=/original/npmrc",
	}, []string{"npm_config_registry", "npm_config_userconfig", "npm_config_script_shell"})
	if err != nil {
		t.Fatalf("newNPMScriptShell() returned unexpected error: %v", err)
	}
	defer func() {
		if err := wrapper.Close(); err != nil {
			t.Errorf("wrapper.Close(): %v", err)
		}
	}()
	script, err := os.ReadFile(wrapper.path)
	if err != nil {
		t.Fatalf("read script shell wrapper: %v", err)
	}
	for _, secret := range []string{originalRegistry, "user:pass", "signature=secret", "/original/npmrc"} {
		if bytes.Contains(script, []byte(secret)) {
			t.Errorf("script shell wrapper persists original environment value %q", secret)
		}
	}
	command := exec.Command(wrapper.path, "-c", `printf '%s|%s|%s' "$npm_config_registry" "$npm_config_userconfig" "$npm_config_script_shell"`)
	command.Env = npmProxyEnvironment(wrapper.environment, map[string]string{
		"npm_config_registry":     "http://127.0.0.1:1234/proxy/",
		"npm_config_userconfig":   "/dev/fd/3",
		"npm_config_script_shell": wrapper.path,
	})
	output, err := command.Output()
	if err != nil {
		t.Fatalf("script shell wrapper: %v", err)
	}
	if got, want := string(output), originalRegistry+"|/original/npmrc|"; got != want {
		t.Errorf("restored environment = %q, want %q", got, want)
	}
}

func TestRunNPMNestedCommandUsesOriginalRegistryConfiguration(t *testing.T) {
	npmExecutable, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is not installed")
	}
	directory := t.TempDir()
	packageJSON := `{"name":"proxy-nested-test","version":"1.0.0","scripts":{"nested":"npm config get registry > nested-registry.txt"}}`
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(packageJSON), 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	}()
	t.Setenv("npm_config_registry", "https://original.example.test/")

	if err := RunNPM(context.Background(), npmExecutable, []string{"run", "nested"}, Streams{Stdout: io.Discard, Stderr: io.Discard}, Options{}); err != nil {
		t.Fatalf("RunNPM() nested command returned unexpected error: %v", err)
	}
	registry, err := os.ReadFile(filepath.Join(directory, "nested-registry.txt"))
	if err != nil {
		t.Fatalf("read nested registry output: %v", err)
	}
	if got, want := strings.TrimSpace(string(registry)), "https://original.example.test/"; got != want {
		t.Errorf("nested npm registry = %q, want original %q", got, want)
	}
}

func TestRunNPMConfigurationMutationFailsWithoutChangingOriginal(t *testing.T) {
	npmExecutable, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is not installed")
	}
	npmrcPath := filepath.Join(t.TempDir(), ".npmrc")
	original := []byte("registry=https://registry.npmjs.org/\nfund=true\n")
	if err := os.WriteFile(npmrcPath, original, 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}
	t.Setenv("npm_config_userconfig", npmrcPath)

	err = RunNPM(context.Background(), npmExecutable, []string{"config", "set", "fund", "false"}, Streams{Stdout: io.Discard, Stderr: io.Discard}, Options{})
	if err == nil {
		t.Fatal("RunNPM() configuration mutation succeeded with read-only inherited config")
	}
	after, readErr := os.ReadFile(npmrcPath)
	if readErr != nil {
		t.Fatalf("read npmrc after mutation attempt: %v", readErr)
	}
	if !bytes.Equal(after, original) {
		t.Errorf("npmrc changed: got %q, want %q", after, original)
	}
}

func TestRunNPMRejectsNPM7(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "npm")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then printf '7.24.2\n'; exit 0; fi
if [ "$1" = "config" ]; then printf '{"registry":"https://registry.example.com/"}\n'; exit 0; fi
if [ "$1" = "prefix" ]; then pwd; exit 0; fi
exit 99
`
	if err := os.WriteFile(executablePath, []byte(script), 0o700); err != nil {
		t.Fatalf("write npm fixture: %v", err)
	}
	err := RunNPM(context.Background(), executablePath, []string{"install", "pkg"}, Streams{}, Options{})
	if err == nil || !strings.Contains(err.Error(), "npm 8 or later") {
		t.Fatalf("RunNPM() error = %v, want npm version requirement", err)
	}
}

func TestValidateNPMProxyArgsRejectsConfigurationFlags(t *testing.T) {
	for _, args := range [][]string{
		{"install", "pkg", "--registry=https://registry.example.com/"},
		{"--prefix", "/tmp/project", "install"},
		{"install", "--@private:registry", "https://private.example.com/"},
		{"view", "pkg", "--https-proxy=http://proxy.example.com/"},
		{"whoami", "--//registry.example.com/:_authToken=secret"},
		{"install", "pkg", "--omit-lockfile-registry-resolved=false"},
		{"install", "pkg", "--no-omit-lockfile-registry-resolved"},
		{"install", "pkg", "--replace-registry-host=never"},
		{"install", "pkg", "--no-strict-ssl"},
		{"install", "pkg", "--reg=https://registry.example.com/"},
		{"-C", "/tmp/project", "install", "pkg"},
		{"-C/tmp/project", "install", "pkg"},
		{"config", "set", "fund", "false", "--global"},
		{"config", "set", "fund", "false", "-g"},
		{"config", "set", "fund", "false", "-L", "project"},
		{"-gl", "config", "set", "fund", "false"},
		{"install", "pkg", "-prefix=/tmp/project"},
		{"install", "pkg", "-proxy=http://proxy.example.com/"},
		{"install", "pkg", "-https-proxy=http://proxy.example.com/"},
		{"install", "pkg", "-ca=fixture"},
		{"install", "pkg", "-cert=fixture"},
		{"install", "pkg", "-key=fixture"},
		{"install", "pkg", "-noproxy=example.com"},
		{"install", "-@private:registry=https://private.example.com/", "pkg"},
	} {
		if err := validateNPMProxyArgs(args); err == nil {
			t.Errorf("validateNPMProxyArgs(%v) = nil, want conflict", args)
		}
	}
	if err := validateNPMProxyArgs([]string{"install", "pkg", "--save-dev"}); err != nil {
		t.Fatalf("validateNPMProxyArgs() rejected ordinary arguments: %v", err)
	}
	if err := validateNPMProxyArgs([]string{"run", "build", "--", "--registry=test"}); err != nil {
		t.Fatalf("validateNPMProxyArgs() rejected script argument after separator: %v", err)
	}
}

func TestLoadLockfileDestinationsRejectsAmbiguousPathsWithoutLeakingURLs(t *testing.T) {
	directory := t.TempDir()
	lockfile := `{"packages":{"one":{"resolved":"https://one.example/artifact.tgz?x=1"},"two":{"resolved":"https://two.example/artifact.tgz?x=1"}}}`
	if err := os.WriteFile(filepath.Join(directory, "package-lock.json"), []byte(lockfile), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	_, err := loadLockfileDestinations(directory)
	if err == nil {
		t.Fatal("loadLockfileDestinations() = nil error, want ambiguity")
	}
	for _, secret := range []string{"one.example", "two.example", "artifact.tgz", "x=1"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("ambiguity error leaks %q: %v", secret, err)
		}
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", value, err)
	}
	return parsed
}
