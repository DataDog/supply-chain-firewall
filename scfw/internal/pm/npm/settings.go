// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
	if npm.npx {
		args = args[:npxOptionsEnd(args)]
	}
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
	// A command-line global value overrides the environment's, as in npm.
	global := firstNonEmpty(nodeproxy.LastValue(options["global"]), nodeproxy.LastValue(environment["global"])) == "true" ||
		nodeproxy.LastValue(options["location"]) == "global" || nodeproxy.LastValue(environment["location"]) == "global"
	if !global {
		prefix := path(options, "prefix")
		if prefix == "" {
			// Only the command line can disable workspaces, as in npm.
			prefix = localPrefix(nodeproxy.LastValue(options["workspaces"]) != "false")
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
		prefix := firstNonEmpty(path(options, "prefix"), path(environment, "prefix"), path(project, "prefix"), path(user, "prefix"), nodeproxy.GlobalPrefix(env))
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
// above cwd containing package.json or node_modules, else cwd. Unless
// workspaces are disabled, a package.json above that directory whose
// "workspaces" include it makes that workspace root the project instead, and the
// workspace's own .npmrc is ignored.
func localPrefix(workspaces bool) string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	nearest := ""
	for dir := cwd; ; dir = filepath.Dir(dir) {
		hasManifest := isRegularFile(filepath.Join(dir, "package.json"))
		switch {
		case nearest == "" && (hasManifest || isDirectory(filepath.Join(dir, "node_modules"))):
			if !workspaces {
				return dir
			}
			nearest = dir
		case nearest != "" && hasManifest && inWorkspaces(dir, nearest):
			return dir
		}
		if filepath.Dir(dir) == dir {
			if nearest != "" {
				return nearest
			}
			return cwd
		}
	}
}

func isRegularFile(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

func isDirectory(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.IsDir()
}

// inWorkspaces reports whether member is a workspace declared by the
// package.json in root, as npm's map-workspaces decides: "workspaces" is a list
// of globs relative to root, or an object holding it as "packages"; "!" globs
// exclude; and a workspace needs a package.json of its own. An unreadable
// manifest declares none.
func inWorkspaces(root, member string) bool {
	if !isRegularFile(filepath.Join(member, "package.json")) {
		return false
	}
	patterns := npmWorkspacePatterns(root)
	relative, err := filepath.Rel(root, member)
	if err != nil {
		return false
	}
	relative = filepath.ToSlash(relative)
	if globIgnoresCase {
		relative = strings.ToLower(relative)
	}
	segments := strings.Split(relative, "/")
	included := false
	for _, pattern := range patterns {
		pattern, excluded := strings.CutPrefix(pattern, "!")
		for _, expanded := range nodeproxy.ExpandBraces(pattern) {
			expanded = strings.Trim(strings.TrimPrefix(expanded, "./"), "/")
			if globIgnoresCase {
				expanded = strings.ToLower(expanded)
			}
			// An exclusion left unexpanded (a range, extglob, POSIX class, or an
			// expansion over budget) excludes every member, so SCFW never reads
			// the root's settings where npm would not.
			if excluded && (strings.ContainsAny(expanded, "{(") || strings.Contains(expanded, "[[:")) {
				return false
			}
			if matchSegments(strings.Split(expanded, "/"), segments) {
				if excluded {
					return false
				}
				included = true
			}
		}
	}
	return included
}

// globIgnoresCase is true where npm's glob matches workspaces case-insensitively.
var globIgnoresCase = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

func npmWorkspacePatterns(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil
	}
	var manifest struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &manifest) != nil {
		return nil
	}
	var patterns []string
	var object struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(manifest.Workspaces, &patterns) != nil {
		if json.Unmarshal(manifest.Workspaces, &object) != nil {
			return nil
		}
		patterns = object.Packages
	}
	return patterns
}

// matchSegments matches glob segments against path segments: "**" spans any
// number of segments, and, as in glob, other wildcards skip dot directories
// unless the pattern segment starts with a dot.
func matchSegments(pattern, path []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			for skipped := 0; skipped <= len(path); skipped++ {
				if matchSegments(pattern[1:], path[skipped:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 || !nodeproxy.MatchSegment(pattern[0], path[0]) {
			return false
		}
		pattern, path = pattern[1:], path[1:]
	}
	return len(path) == 0
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
