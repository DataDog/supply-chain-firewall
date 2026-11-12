// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// registryCA is a per-registry CA setting; Key is "//host[:port]/path/".
type registryCA struct{ Key, CAFile, CA string }

// pnpmSettings is the configuration pnpm would use for one command before SCFW
// overrides it.
type pnpmSettings struct {
	// HTTPS and HTTP are the upstream proxies pnpm would use for each scheme.
	HTTPS, HTTP string
	NoProxy     string
	// NoProxyAll is noproxy=true, which bypasses the proxy for every host.
	NoProxyAll  bool
	CAFile      string
	CA          []string
	RegistryCAs []registryCA
	StrictSSL   bool
	Registries  []string
}

func (p Pnpm) settings(command []string) (pnpmSettings, error) {
	major, err := p.major(command)
	if err != nil {
		return pnpmSettings{}, err
	}
	parsed := parseCommand(major, p.dlx, command)
	dir, err := os.Getwd()
	if err != nil {
		return pnpmSettings{}, errors.New("could not resolve pnpm directory")
	}
	if parsed.dir != "" {
		if filepath.IsAbs(parsed.dir) {
			dir = filepath.Clean(parsed.dir)
		} else {
			dir = filepath.Join(dir, parsed.dir)
		}
	}
	return p.npmrcSettings(parsed, dir)
}

// layers resolves settings across configuration layers, highest precedence
// first. The first layer that sets a key decides; "null" unsets it there.
type layers []nodeproxy.Config

func (all layers) values(key string) ([]string, bool) {
	for _, layer := range all {
		if values, found := layer[key]; found {
			if nodeproxy.LastValue(values) == "null" {
				return nil, false
			}
			return values, true
		}
	}
	return nil, false
}

func (all layers) scalar(key string) (string, bool) {
	values, found := all.values(key)
	return nodeproxy.LastValue(values), found
}

var registryCAKey = regexp.MustCompile(`^(//.*):(ca|cafile)$`)

// registryCAs collects per-registry CA settings; the first layer setting a key wins.
func (all layers) registryCAs(home string) []registryCA {
	seen := map[string]bool{}
	var keys []string
	for _, layer := range all {
		for key := range layer {
			if registryCAKey.MatchString(key) && !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	var cas []registryCA
	for _, key := range keys {
		value, _ := all.scalar(key)
		match := registryCAKey.FindStringSubmatch(key)
		if match[2] == "cafile" {
			cas = append(cas, registryCA{Key: match[1], CAFile: expandPath(value, home)})
		} else {
			cas = append(cas, registryCA{Key: match[1], CA: value})
		}
	}
	return cas
}

// scopedRegistries lists @scope:registry values, sorted by scope.
func (all layers) scopedRegistries() []string {
	var keys []string
	for _, layer := range all {
		for key := range layer {
			if strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry") && !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	var registries []string
	for _, key := range keys {
		if value, found := all.scalar(key); found {
			registries = append(registries, value)
		}
	}
	return registries
}

// proxyFallback mirrors pnpm 10/11's resolution of the standard proxy variables:
// a configured proxy wins, the lowercase variable is read before the uppercase
// one even when empty, proxy=false disables the fallback, and HTTP falls back
// to the HTTPS proxy.
func proxyFallback(all layers, env map[string]string) (https, http string) {
	lookup := func(name string) (string, bool) {
		if value, found := env[name]; found {
			return value, true
		}
		value, found := env[strings.ToUpper(name)]
		return value, found
	}
	first := func(candidates ...func() (string, bool)) (string, bool) {
		for _, candidate := range candidates {
			if value, found := candidate(); found {
				return value, true
			}
		}
		return "", false
	}
	setting := func(key string) func() (string, bool) { return func() (string, bool) { return all.scalar(key) } }
	variable := func(name string) func() (string, bool) { return func() (string, bool) { return lookup(name) } }

	https, httpsFound := "", false
	if value, _ := all.scalar("https-proxy"); value != "" && value != "false" {
		https, httpsFound = value, true
	} else {
		https, httpsFound = first(setting("proxy"), variable("https_proxy"))
	}
	if value, _ := all.scalar("http-proxy"); value != "" && value != "false" {
		http = value
	} else {
		http, _ = first(func() (string, bool) { return https, httpsFound }, variable("http_proxy"), variable("proxy"))
	}
	if https == "false" {
		https = ""
	}
	if http == "false" {
		http = ""
	}
	return https, http
}

// noProxy mirrors pnpm's no-proxy, then noproxy, then the no_proxy variables.
func noProxy(all layers, env map[string]string) (string, bool) {
	value, _ := all.scalar("no-proxy")
	if value == "" || value == "false" {
		var found bool
		if value, found = all.scalar("noproxy"); !found {
			if value, found = env["no_proxy"]; !found {
				value = env["NO_PROXY"]
			}
		}
	}
	if value == "true" {
		return "", true
	}
	return value, false
}

// readWorkspaceSettings reads the settings of a pnpm-workspace.yaml as kebab-case
// keys. A missing file has no settings.
func readWorkspaceSettings(path string) (nodeproxy.Config, error) {
	data, err := nodeproxy.ReadConfigFile(path)
	if os.IsNotExist(err) || os.IsPermission(err) || errors.Is(err, syscall.ENOTDIR) {
		return nodeproxy.Config{}, nil
	}
	if err != nil {
		return nil, errors.New("could not read pnpm configuration")
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, errors.New("could not read pnpm configuration")
	}
	config := nodeproxy.Config{}
	for key, value := range document {
		switch typed := value.(type) {
		case nil, map[string]any:
		case []any:
			for _, item := range typed {
				config[kebab(key)] = append(config[kebab(key)], fmt.Sprint(item))
			}
		default:
			config[kebab(key)] = []string{fmt.Sprint(typed)}
		}
	}
	return config, nil
}

var upperLetter = regexp.MustCompile(`[A-Z]`)

func kebab(name string) string {
	return upperLetter.ReplaceAllStringFunc(name, func(letter string) string { return "-" + strings.ToLower(letter) })
}

// destinationKey reports settings that pnpm will not take from an untrusted
// project file when they contain an environment placeholder.
func destinationKey(key string) bool {
	return key == "registry" || key == "https-proxy" || key == "http-proxy" || key == "proxy" ||
		strings.HasPrefix(key, "//") || strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry")
}

func dropPlaceholders(config nodeproxy.Config, keys func(string) bool) {
	for key, values := range config {
		if keys(key) && slices.ContainsFunc(values, func(value string) bool { return strings.Contains(value, "${") }) {
			delete(config, key)
		}
	}
}

// loadNpmrc reads an npmrc file. Project and workspace files are untrusted:
// destinations that reference environment variables are dropped.
func loadNpmrc(path string, env map[string]string, untrusted bool) (nodeproxy.Config, error) {
	if !untrusted {
		return nodeproxy.LoadNpmrc(path, env)
	}
	raw, err := nodeproxy.LoadNpmrc(path, nil)
	if err != nil {
		return nil, err
	}
	dropPlaceholders(raw, destinationKey)
	return nodeproxy.ExpandConfig(raw, env), nil
}

// configDir is pnpm's global configuration directory.
func configDir(env map[string]string) string {
	if env["XDG_CONFIG_HOME"] != "" {
		return filepath.Join(env["XDG_CONFIG_HOME"], "pnpm")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(env["HOME"], "Library", "Preferences", "pnpm")
	}
	return filepath.Join(env["HOME"], ".config", "pnpm")
}

// workspaceRoot is the nearest directory at or above dir with pnpm-workspace.yaml.
func workspaceRoot(dir string) string {
	for current := dir; ; current = filepath.Dir(current) {
		if regularFile(filepath.Join(current, "pnpm-workspace.yaml")) {
			return current
		}
		if filepath.Dir(current) == current {
			return ""
		}
	}
}

// localPrefix is pnpm's project directory: the nearest directory at or above
// dir with a manifest, node_modules, or pnpm-workspace.yaml, else dir.
func localPrefix(dir string) string {
	for current := dir; ; current = filepath.Dir(current) {
		for _, name := range []string{"package.json", "package.json5", "package.yaml", "pnpm-workspace.yaml", "node_modules"} {
			if _, err := os.Stat(filepath.Join(current, name)); err == nil {
				return current
			}
		}
		if filepath.Dir(current) == current {
			return dir
		}
	}
}

// expandPath resolves a path setting: a leading ~ is the home directory and
// relative paths are relative to the working directory.
func expandPath(value, home string) string {
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
