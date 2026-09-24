// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package packagemanager transforms supported package-manager commands so their
// network traffic passes through and trusts the SCFW proxy without changing any
// package-manager configuration file.
package packagemanager

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

var supportedNames = []string{"npm", "yarn", "pnpm", "bun", "pip", "pip3", "poetry", "uv", "mvn", "mvnw"}

const mavenTrustStorePassword = "scfw-proxy"

var bunPackageCommands = []string{
	"add", "ci", "install", "link", "outdated", "patch", "remove", "unlink", "update",
}

var bunGlobalOptionsWithValue = []string{"--config", "--cwd", "--env-file", "--loader", "--preload", "-c", "-r"}

// Command builds a child process configured to use the proxy and trust its CA.
func Command(ctx context.Context, command []string, proxyURL, certificatePath string) (*exec.Cmd, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no package manager command specified")
	}

	name := filepath.Base(command[0])
	if !slices.Contains(supportedNames, name) {
		return nil, fmt.Errorf("unsupported package manager %q (supported: %s)", name, strings.Join(supportedNames, ", "))
	}

	executable, err := exec.LookPath(command[0])
	if err != nil {
		return nil, fmt.Errorf("find %s executable: %w", name, err)
	}

	arguments := slices.Clone(command[1:])
	if name == "bun" {
		arguments = bunArguments(arguments, certificatePath)
	}
	var mavenTrustStore string
	if name == "mvn" || name == "mvnw" {
		mavenTrustStore, err = createMavenTrustStore(ctx, certificatePath)
		if err != nil {
			return nil, err
		}
	}

	child := exec.CommandContext(ctx, executable, arguments...)
	child.Env, err = proxyEnvironment(os.Environ(), name, proxyURL, certificatePath, mavenTrustStore)
	if err != nil {
		return nil, err
	}
	return child, nil
}

func createMavenTrustStore(ctx context.Context, certificatePath string) (string, error) {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		javaHome := os.Getenv("JAVA_HOME")
		if javaHome == "" {
			return "", fmt.Errorf("find keytool executable required by Maven: %w", err)
		}
		javaHomeKeytool := filepath.Join(javaHome, "bin", "keytool")
		keytool, err = exec.LookPath(javaHomeKeytool)
		if err != nil {
			return "", fmt.Errorf("find keytool executable required by Maven: %w", err)
		}
	}

	trustStorePath := filepath.Join(filepath.Dir(certificatePath), "maven-truststore.p12")
	command := exec.CommandContext(ctx, keytool,
		"-importcert",
		"-noprompt",
		"-alias", "scfw-proxy-ca",
		"-file", certificatePath,
		"-keystore", trustStorePath,
		"-storetype", "PKCS12",
		"-storepass", mavenTrustStorePassword,
	)
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("create Maven trust store: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(trustStorePath, 0o600); err != nil {
		return "", fmt.Errorf("secure Maven trust store: %w", err)
	}
	return trustStorePath, nil
}

func bunArguments(arguments []string, certificatePath string) []string {
	index := bunPackageCommandIndex(arguments)
	if index == -1 {
		return arguments
	}

	transformed := make([]string, 0, len(arguments)+2)
	transformed = append(transformed, arguments[:index+1]...)
	transformed = append(transformed, "--cafile", certificatePath)
	return append(transformed, arguments[index+1:]...)
}

func bunPackageCommandIndex(arguments []string) int {
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "--":
			return -1
		case slices.Contains(bunPackageCommands, argument):
			return index
		case slices.Contains(bunGlobalOptionsWithValue, argument):
			index++
		case strings.HasPrefix(argument, "-"):
			continue
		default:
			return -1
		}
	}
	return -1
}

func proxyEnvironment(environment []string, name, proxyURL, certificatePath, mavenTrustStore string) ([]string, error) {
	overrides := map[string]string{
		"GIT_SSL_CAINFO": certificatePath,
		"HTTP_PROXY":     proxyURL,
		"HTTPS_PROXY":    proxyURL,
		"NO_PROXY":       "",
		"http_proxy":     proxyURL,
		"https_proxy":    proxyURL,
		"no_proxy":       "",
	}
	switch name {
	case "npm", "pnpm":
		overrides["NODE_EXTRA_CA_CERTS"] = certificatePath
		overrides["npm_config_cafile"] = certificatePath
		overrides["npm_config_https_proxy"] = proxyURL
		overrides["npm_config_noproxy"] = ""
		overrides["npm_config_proxy"] = proxyURL
	case "yarn":
		overrides["NODE_EXTRA_CA_CERTS"] = certificatePath
		overrides["YARN_HTTP_PROXY"] = proxyURL
		overrides["YARN_HTTPS_CA_FILE_PATH"] = certificatePath
		overrides["YARN_HTTPS_PROXY"] = proxyURL
	case "bun":
		overrides["NODE_EXTRA_CA_CERTS"] = certificatePath
	case "pip", "pip3":
		overrides["PIP_CERT"] = certificatePath
		overrides["PIP_PROXY"] = proxyURL
		overrides["REQUESTS_CA_BUNDLE"] = certificatePath
	case "poetry":
		overrides["REQUESTS_CA_BUNDLE"] = certificatePath
	case "uv":
		overrides["SSL_CERT_FILE"] = certificatePath
	case "mvn", "mvnw":
		if mavenTrustStore == "" {
			return nil, fmt.Errorf("missing Maven trust store path")
		}
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil || parsedProxyURL.Hostname() == "" || parsedProxyURL.Port() == "" {
			return nil, fmt.Errorf("parse Maven proxy URL %q", proxyURL)
		}
		jvmOptions := strings.Join([]string{
			"-Daether.connector.http.useSystemProperties=true",
			"-Daether.transport.apache.useSystemProperties=true",
			"-Dhttp.proxyHost=" + parsedProxyURL.Hostname(),
			"-Dhttp.proxyPort=" + parsedProxyURL.Port(),
			"-Dhttps.proxyHost=" + parsedProxyURL.Hostname(),
			"-Dhttps.proxyPort=" + parsedProxyURL.Port(),
			"-Dhttp.nonProxyHosts=",
			"-Djavax.net.ssl.trustStore=" + mavenTrustStore,
			"-Djavax.net.ssl.trustStorePassword=" + mavenTrustStorePassword,
			"-Djavax.net.ssl.trustStoreType=PKCS12",
		}, " ")
		overrides["MAVEN_OPTS"] = appendEnvironmentValue(environmentValue(environment, "MAVEN_OPTS"), jvmOptions)
		overrides["MAVEN_ARGS"] = appendEnvironmentValue(
			environmentValue(environment, "MAVEN_ARGS"),
			"-Daether.connector.http.useSystemProperties=true -Daether.transport.apache.useSystemProperties=true",
		)
	}

	result := make([]string, 0, len(environment)+len(overrides))
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if _, overridden := overrides[key]; !found || !overridden {
			result = append(result, entry)
		}
	}
	keys := []string{"GIT_SSL_CAINFO", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
	for key := range overrides {
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		result = append(result, key+"="+overrides[key])
	}
	return result, nil
}

func environmentValue(environment []string, wantedKey string) string {
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found && key == wantedKey {
			return value
		}
	}
	return ""
}

func appendEnvironmentValue(existing, addition string) string {
	if strings.TrimSpace(existing) == "" {
		return addition
	}
	return existing + " " + addition
}
