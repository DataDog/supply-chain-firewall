// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// npmrcSettings mirrors pnpm 10's layers, highest first: command options,
// pnpm-workspace.yaml (which pnpm 10 ranks above the environment), npm_config_*
// variables, the project and workspace .npmrc, the user and global npmrc, and
// pnpm's own rc file.
func (p Pnpm) npmrcSettings(parsed parsedCommand, dir string) (pnpmSettings, error) {
	environ := os.Environ()
	env := nodeproxy.LookupEnvironment(environ)
	home := env["HOME"]
	environment := nodeproxy.EnvironmentConfig(environ)

	workspace := workspaceRoot(dir)
	workspaceSettings := nodeproxy.Config{}
	var workspaceNpmrc nodeproxy.Config
	if workspace != "" {
		var err error
		if workspaceSettings, err = readWorkspaceSettings(filepath.Join(workspace, "pnpm-workspace.yaml")); err != nil {
			return pnpmSettings{}, err
		}
		// pnpm 10 computes registries before applying these settings, ignores
		// cafile there, and drops proxies that reference the environment.
		for key := range workspaceSettings {
			if key == "registry" || key == "cafile" || strings.HasSuffix(key, ":registry") {
				delete(workspaceSettings, key)
			}
		}
		dropPlaceholders(workspaceSettings, func(key string) bool {
			return key == "registry" || key == "https-proxy" || key == "http-proxy" || key == "proxy" || key == "no-proxy" || key == "noproxy"
		})
		if workspaceNpmrc, err = loadNpmrc(filepath.Join(workspace, ".npmrc"), env, true); err != nil {
			return pnpmSettings{}, err
		}
	}
	project := nodeproxy.Config{}
	if !parsed.global {
		var err error
		if project, err = loadNpmrc(filepath.Join(localPrefix(dir), ".npmrc"), env, true); err != nil {
			return pnpmSettings{}, err
		}
	}
	// User and global files come from trusted layers only.
	userconfig := nodeproxy.LastValue(parsed.network["userconfig"])
	if userconfig == "" {
		userconfig = nodeproxy.LastValue(environment["userconfig"])
	}
	userconfig = expandPath(userconfig, home)
	if userconfig == "" {
		userconfig = filepath.Join(home, ".npmrc")
	}
	user, err := loadNpmrc(userconfig, env, false)
	if err != nil {
		return pnpmSettings{}, err
	}
	globalconfig := expandPath(nodeproxy.LastValue(environment["globalconfig"]), home)
	if globalconfig == "" {
		prefix := nodeproxy.LastValue(environment["prefix"])
		if prefix == "" {
			prefix = nodeproxy.GlobalPrefix(env)
		}
		if prefix != "" {
			globalconfig = filepath.Join(prefix, "etc", "npmrc")
		}
	}
	global, err := loadNpmrc(globalconfig, env, false)
	if err != nil {
		return pnpmSettings{}, err
	}
	rc, err := loadNpmrc(filepath.Join(configDir(env), "rc"), env, false)
	if err != nil {
		return pnpmSettings{}, err
	}

	files := layers{environment, project, workspaceNpmrc, user, global, rc}
	all := append(layers{parsed.network, workspaceSettings}, files...)
	if err := all.refused(); err != nil {
		return pnpmSettings{}, err
	}
	var settings pnpmSettings
	settings.HTTPS, settings.HTTP = proxyFallback(all, env, false)
	settings.NoProxy, settings.NoProxyAll = noProxy(all, env)
	if cafile, _ := all.scalar("cafile"); cafile != "" {
		settings.CAFile = expandPath(cafile, home)
	}
	settings.CA, _ = all.values("ca")
	settings.RegistryCAs = all.registryCAs(home)
	strictSSL, _ := all.scalar("strict-ssl")
	settings.StrictSSL = strictSSL != "false"

	registries := append(layers{parsed.network}, files...)
	registries = append(registries, nodeproxy.Config{"@jsr:registry": {"https://npm.jsr.io/"}})
	registry, _ := registries.scalar("registry")
	if registry == "" {
		registry = "https://registry.npmjs.org/"
	}
	settings.Registries = append([]string{registry}, registries.scopedRegistries()...)
	return settings, nil
}
