// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// npmrcKeys are the settings pnpm 11 and 12 still read from .npmrc files.
var npmrcKeys = []string{
	"ca", "cafile", "cert", "key", "registry", "https-proxy", "proxy", "no-proxy", "http-proxy", "local-address", "strict-ssl",
}

// yamlSettings mirrors pnpm 11 and 12, highest first: command options,
// pnpm_config_* variables, pnpm-workspace.yaml, the global config.yaml, and
// then the workspace .npmrc, auth.ini, and the user .npmrc, which keep only
// registry, network, and authentication settings. pnpm 12 reads no CA from
// YAML or the environment.
func (p Pnpm) yamlSettings(major int, parsed parsedCommand, dir string) (pnpmSettings, error) {
	environ := os.Environ()
	env := nodeproxy.LookupEnvironment(environ)
	home := env["HOME"]
	environment := pnpmEnvironmentConfig(environ, major)

	root := workspaceRoot(dir)
	if root == "" {
		root = localPrefix(dir)
	}
	workspace, err := readWorkspaceSettings(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return pnpmSettings{}, err
	}
	global, err := readWorkspaceSettings(filepath.Join(configDir(env), "config.yaml"))
	if err != nil {
		return pnpmSettings{}, err
	}
	if major >= 12 {
		for _, layer := range []nodeproxy.Config{environment, workspace, global} {
			delete(layer, "ca")
			delete(layer, "cafile")
		}
	}
	// CA files are loaded only from .npmrc and the command line.
	delete(workspace, "cafile")
	delete(global, "cafile")

	project, err := loadNpmrc(filepath.Join(root, ".npmrc"), env, true)
	if err != nil {
		return pnpmSettings{}, err
	}
	auth, err := loadNpmrc(filepath.Join(configDir(env), "auth.ini"), env, false)
	if err != nil {
		return pnpmSettings{}, err
	}
	// The user file is the first of the command line's npmrc-auth-file and
	// userconfig, the same pair from the environment, config.yaml's
	// npmrcAuthFile, and npm_config_userconfig.
	userconfig := ""
	for _, values := range [][]string{
		parsed.network["npmrc-auth-file"], parsed.network["userconfig"],
		environment["npmrc-auth-file"], environment["userconfig"],
		global["npmrc-auth-file"], nodeproxy.EnvironmentConfig(environ)["userconfig"],
	} {
		if userconfig = nodeproxy.LastValue(values); userconfig != "" {
			break
		}
	}
	userconfig = expandPath(userconfig, home)
	if userconfig == "" {
		userconfig = filepath.Join(home, ".npmrc")
	}
	user, err := loadNpmrc(userconfig, env, false)
	if err != nil {
		return pnpmSettings{}, err
	}
	readableNpmrc(project, root)
	readableNpmrc(auth, configDir(env))
	readableNpmrc(user, filepath.Dir(userconfig))

	all := layers{parsed.network, environment, workspace, global, project, auth, user}
	if err := all.refused(); err != nil {
		return pnpmSettings{}, err
	}
	var settings pnpmSettings
	settings.HTTPS, settings.HTTP = proxyFallback(all, env, major >= 12)
	settings.NoProxy, settings.NoProxyAll = noProxy(all, env)
	cafiles := layers{parsed.network, project, auth, user}
	if cafile, _ := cafiles.scalar("cafile"); cafile != "" {
		settings.CAFile = expandPath(cafile, home)
	}
	settings.CA, _ = all.values("ca")
	settings.RegistryCAs = all.registryCAs(home)
	strictSSL, _ := all.scalar("strict-ssl")
	settings.StrictSSL = strictSSL != "false"
	registries := append(all, nodeproxy.Config{"@jsr:registry": {"https://npm.jsr.io/"}})
	registry, _ := registries.scalar("registry")
	if registry == "" {
		registry = "https://registry.npmjs.org/"
	}
	settings.Registries = append([]string{registry}, registries.scopedRegistries()...)
	return settings, nil
}

// readableNpmrc keeps the keys pnpm 11 and 12 read from an .npmrc file and
// resolves relative CA files against the file's directory.
func readableNpmrc(config nodeproxy.Config, dir string) {
	for key, values := range config {
		switch {
		case strings.HasPrefix(key, "@"), strings.HasPrefix(key, "_"), key == "email", key == "username":
		case strings.HasPrefix(key, "//"):
			if strings.HasSuffix(key, ":cafile") {
				config[key] = relativeTo(values, dir)
			}
		case key == "cafile":
			config[key] = relativeTo(values, dir)
		case !slices.Contains(npmrcKeys, key):
			delete(config, key)
		}
	}
}

func relativeTo(values []string, dir string) []string {
	resolved := make([]string, len(values))
	for index, value := range values {
		resolved[index] = value
		if value != "" && !filepath.IsAbs(value) && !strings.HasPrefix(value, "~") {
			resolved[index] = filepath.Join(dir, value)
		}
	}
	return resolved
}

// pnpmEnvironmentConfig mirrors pnpm 11 and 12's environment layer: only the
// exact pnpm_config_<lower_snake> and PNPM_CONFIG_<UPPER_SNAKE> forms count,
// and URL settings ignore empty values. pnpm 11 keeps the last variant; pnpm 12
// prefers the uppercase one and ignores every empty value.
func pnpmEnvironmentConfig(environ []string, major int) nodeproxy.Config {
	config, upper := nodeproxy.Config{}, nodeproxy.Config{}
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		target := config
		name, found := strings.CutPrefix(key, "pnpm_config_")
		if !found || name != strings.ToLower(name) {
			if name, found = strings.CutPrefix(key, "PNPM_CONFIG_"); !found || name != strings.ToUpper(name) {
				continue
			}
			if major >= 12 {
				target = upper
			}
		}
		name = strings.ReplaceAll(strings.ToLower(name), "_", "-")
		if name == "" || value == "" && (major >= 12 || name == "https-proxy" || name == "proxy" || name == "registry") {
			continue
		}
		target[name] = []string{value}
	}
	for name, values := range upper {
		config[name] = values
	}
	return config
}
