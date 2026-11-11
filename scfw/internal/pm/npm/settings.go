// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// npmDiscoveryResult is the configuration npm would use for one command before
// SCFW overrides it. Where npm versions differ, npm 11 behavior is followed:
// the command's proxy configuration overrides every variant npm reads, so a
// difference can only select another upstream, which fails, never a bypass.
type npmDiscoveryResult struct {
	// HTTPS and HTTP are the upstream proxies npm would use for each scheme.
	HTTPS, HTTP string
	// NoProxy is npm's bypass list: its noproxy setting, or the environment's
	// no_proxy when that is empty, plus the environment's no_proxy, which
	// @npmcli/agent consults again when it connects.
	NoProxy    string
	CAFile     string
	CA         []string
	StrictSSL  bool
	Registries []string
}

// npmConfig maps an npm configuration key to its values within one layer; a
// scalar setting uses its last value.
type npmConfig = nodeproxy.Config

func (npm Npm) settings(args []string) (npmDiscoveryResult, error) {
	environ := os.Environ()
	layers, err := readNpmConfig(args, environ)
	if err != nil {
		return npmDiscoveryResult{}, err
	}
	home := nodeproxy.LookupEnvironment(environ)["HOME"]
	// A null value is unset in npm (`npm config set proxy null` writes
	// proxy=null), yet it still hides the same key in lower layers.
	get := func(key string) []string {
		for _, layer := range layers {
			if values, found := layer[key]; found {
				var set []string
				for _, value := range values {
					if value != "null" {
						set = append(set, value)
					}
				}
				return set
			}
		}
		return nil
	}
	scalar := func(key string) string {
		values := get(key)
		if len(values) == 0 {
			return ""
		}
		return values[len(values)-1]
	}

	agent := agentEnvironment(environ)
	httpsProxy, proxy := scalar("https-proxy"), scalar("proxy")
	if proxy == "false" {
		proxy = ""
	}
	result := npmDiscoveryResult{
		HTTPS:     firstNonEmpty(httpsProxy, proxy, agent["https_proxy"]),
		HTTP:      firstNonEmpty(httpsProxy, proxy, agent["https_proxy"], agent["http_proxy"], agent["proxy"]),
		CAFile:    expandNpmPath(scalar("cafile"), home),
		CA:        get("ca"),
		StrictSSL: scalar("strict-ssl") != "false",
	}
	noProxy := strings.Join(get("noproxy"), ",")
	if noProxy == "" {
		noProxy = agent["no_proxy"]
	} else if agent["no_proxy"] != "" {
		noProxy += "," + agent["no_proxy"]
	}
	result.NoProxy = noProxy

	result.Registries = []string{firstNonEmpty(scalar("registry"), "https://registry.npmjs.org/")}
	var scopes []string
	for _, layer := range layers {
		for key := range layer {
			if isScopedRegistry(key) && !slices.Contains(scopes, key) {
				scopes = append(scopes, key)
			}
		}
	}
	sort.Strings(scopes)
	for _, key := range scopes {
		result.Registries = append(result.Registries, scalar(key))
	}
	return result, nil
}

// readNpmConfig returns npm's configuration layers, highest precedence first:
// command options, environment, then the project, user, and global npmrc files.
func readNpmConfig(args []string, environ []string) ([]npmConfig, error) {
	env := nodeproxy.LookupEnvironment(environ)
	home := env["HOME"]
	options := nodeproxy.ExpandConfig(optionConfig(parseNpmOptions(args)), env)
	environment := nodeproxy.ExpandConfig(nodeproxy.EnvironmentConfig(environ), env)
	path := func(layer npmConfig, key string) string { return expandNpmPath(nodeproxy.LastValue(layer[key]), home) }

	userconfig := firstNonEmpty(path(options, "userconfig"), path(environment, "userconfig"))
	defaultUserconfig := userconfig
	if defaultUserconfig == "" && home != "" {
		defaultUserconfig = filepath.Join(home, ".npmrc")
	}
	project := npmConfig{}
	global := nodeproxy.LastValue(options["global"]) == "true" || nodeproxy.LastValue(options["location"]) == "global" ||
		nodeproxy.LastValue(environment["global"]) == "true" || nodeproxy.LastValue(environment["location"]) == "global"
	if !global {
		prefix := path(options, "prefix")
		if prefix == "" {
			prefix = localPrefix()
		}
		// Like npm, never load the user config a second time as the project's.
		if file := filepath.Join(prefix, ".npmrc"); file != defaultUserconfig {
			var err error
			if project, err = nodeproxy.LoadNpmrc(file, env); err != nil {
				return nil, err
			}
		}
	}

	if userconfig == "" {
		userconfig = firstNonEmpty(path(project, "userconfig"), defaultUserconfig)
	}
	user, err := nodeproxy.LoadNpmrc(userconfig, env)
	if err != nil {
		return nil, err
	}

	// npm's default globalconfig is an accessor whose setter absorbs the first
	// assignment, in load order (options, environment, project, user), so that
	// value ranks below every later one (npm 10 and 11).
	var setters []string
	for _, layer := range []npmConfig{options, environment, project, user} {
		if value := path(layer, "globalconfig"); value != "" {
			setters = append(setters, value)
		}
	}
	globalconfig := ""
	switch {
	case len(setters) > 1:
		globalconfig = setters[1]
	case len(setters) == 1:
		globalconfig = setters[0]
	default:
		prefix := firstNonEmpty(path(options, "prefix"), path(environment, "prefix"), path(project, "prefix"), path(user, "prefix"), globalPrefix(env))
		if prefix != "" {
			globalconfig = filepath.Join(prefix, "etc", "npmrc")
		}
	}
	globalLayer, err := nodeproxy.LoadNpmrc(globalconfig, env)
	if err != nil {
		return nil, err
	}
	return []npmConfig{options, environment, project, user, globalLayer}, nil
}

// localPrefix mirrors npm's project directory: the nearest directory at or
// above cwd containing package.json or node_modules, else cwd.
func localPrefix() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if info, err := os.Stat(filepath.Join(dir, "package.json")); err == nil && info.Mode().IsRegular() {
			return dir
		}
		if info, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil && info.IsDir() {
			return dir
		}
		if filepath.Dir(dir) == dir {
			return cwd
		}
	}
}

// globalPrefix mirrors npm's default global prefix on Unix: PREFIX, else the
// directory above the bin directory of the node executable npm runs on.
func globalPrefix(env map[string]string) string {
	if env["PREFIX"] != "" {
		return env["PREFIX"]
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return ""
	}
	if node, err = filepath.EvalSymlinks(node); err != nil {
		return ""
	}
	prefix := filepath.Dir(filepath.Dir(node))
	if env["DESTDIR"] != "" {
		prefix = filepath.Join(env["DESTDIR"], prefix)
	}
	return prefix
}

// expandNpmPath resolves an npm path setting: a leading ~ is the home
// directory and relative paths are relative to cwd.
func expandNpmPath(value, home string) string {
	if value == "" {
		return ""
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		value = filepath.Join(home, strings.TrimPrefix(value, "~"))
	}
	if absolute, err := filepath.Abs(value); err == nil {
		return absolute
	}
	return value
}

func optionConfig(options []npmOption) npmConfig {
	config := npmConfig{}
	for _, option := range options {
		config[option.name] = append(config[option.name], option.value)
	}
	return config
}

// agentEnvironment returns the proxy variables @npmcli/agent falls back to,
// matched case-insensitively with the last variant winning.
func agentEnvironment(environ []string) map[string]string {
	values := map[string]string{}
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		switch name := strings.ToLower(key); name {
		case "https_proxy", "http_proxy", "proxy", "no_proxy":
			values[name] = value
		}
	}
	return values
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
