// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
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
	// candidates lists every proxy value npm could select, for validation.
	candidates []string
}

// npmConfig maps an npm configuration key to its values within one layer; a
// scalar setting uses its last value.
type npmConfig map[string][]string

func (npm Npm) settings(args []string) (npmDiscoveryResult, error) {
	environ := os.Environ()
	layers, err := readNpmConfig(args, environ)
	if err != nil {
		return npmDiscoveryResult{}, err
	}
	home := lookupEnvironment(environ)["HOME"]
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
	for _, value := range []string{httpsProxy, proxy, agent["https_proxy"], agent["http_proxy"], agent["proxy"]} {
		if value != "" {
			result.candidates = append(result.candidates, value)
		}
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
	env := lookupEnvironment(environ)
	home := env["HOME"]
	options := expandNpmConfig(optionConfig(parseNpmOptions(args)), env)
	environment := expandNpmConfig(environmentConfig(environ), env)
	path := func(layer npmConfig, key string) string { return expandNpmPath(lastValue(layer[key]), home) }

	userconfig := firstNonEmpty(path(options, "userconfig"), path(environment, "userconfig"))
	defaultUserconfig := userconfig
	if defaultUserconfig == "" && home != "" {
		defaultUserconfig = filepath.Join(home, ".npmrc")
	}
	project := npmConfig{}
	global := lastValue(options["global"]) == "true" || lastValue(options["location"]) == "global" ||
		lastValue(environment["global"]) == "true" || lastValue(environment["location"]) == "global"
	if !global {
		prefix := path(options, "prefix")
		if prefix == "" {
			prefix = localPrefix()
		}
		// Like npm, never load the user config a second time as the project's.
		if file := filepath.Join(prefix, ".npmrc"); file != defaultUserconfig {
			var err error
			if project, err = loadNpmrc(file, env); err != nil {
				return nil, err
			}
		}
	}

	if userconfig == "" {
		userconfig = firstNonEmpty(path(project, "userconfig"), defaultUserconfig)
	}
	user, err := loadNpmrc(userconfig, env)
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
	globalLayer, err := loadNpmrc(globalconfig, env)
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

func loadNpmrc(path string, env map[string]string) (npmConfig, error) {
	if path == "" {
		return npmConfig{}, nil
	}
	data, err := readNpmrcFile(path)
	if os.IsNotExist(err) || os.IsPermission(err) || errors.Is(err, syscall.ENOTDIR) {
		return npmConfig{}, nil
	}
	if err != nil {
		return nil, errors.New("could not read npm configuration")
	}
	return readNpmrc(data, env), nil
}

const maxNpmrcBytes = 8 << 20

func readNpmrcFile(path string) ([]byte, error) {
	// Nonblocking open plus a regular-file check also handles a path swapped
	// for a FIFO while discovery is reading it.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("npm configuration requires a regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxNpmrcBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxNpmrcBytes {
		return nil, errors.New("npm configuration is too large")
	}
	return body, nil
}

// readNpmrc parses an npmrc file as npm's ini package does. Keys inside a
// [section] are not top-level settings, so npm ignores them.
func readNpmrc(data []byte, env map[string]string) npmConfig {
	config := npmConfig{}
	inSection := false
	text := strings.TrimPrefix(string(data), string(rune(0xFEFF)))
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' }) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = true
			continue
		}
		rawKey, rawValue, assigned := strings.Cut(line, "=")
		key := unquoteIniValue(rawKey)
		if inSection || key == "" {
			continue
		}
		value := "true"
		if assigned {
			value = unquoteIniValue(rawValue)
		}
		if name, isArray := strings.CutSuffix(key, "[]"); isArray && name != "" {
			config[name] = append(config[name], value)
		} else {
			config[key] = []string{value}
		}
	}
	return expandNpmConfig(config, env)
}

// unquoteIniValue mirrors the ini package: a quoted value is JSON-decoded when
// possible; otherwise an unescaped ; or # starts a comment.
func unquoteIniValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		if value[0] == '\'' {
			value = value[1 : len(value)-1]
		}
		var decoded string
		if json.Unmarshal([]byte(value), &decoded) == nil {
			return decoded
		}
		return value
	}
	var unescaped strings.Builder
	escaped := false
	for _, character := range value {
		switch {
		case escaped:
			if !strings.ContainsRune(`\;#`, character) {
				unescaped.WriteByte('\\')
			}
			unescaped.WriteRune(character)
			escaped = false
		case character == ';' || character == '#':
			return strings.TrimSpace(unescaped.String())
		case character == '\\':
			escaped = true
		default:
			unescaped.WriteRune(character)
		}
	}
	if escaped {
		unescaped.WriteByte('\\')
	}
	return strings.TrimSpace(unescaped.String())
}

var npmEnvironmentReference = regexp.MustCompile(`(\\*)\$\{([^${}?]+)(\?)?\}`)

// expandNpmConfig applies npm's ${VAR} substitution to keys and values. An
// unset variable stays literal unless written ${VAR?}; an odd number of
// preceding backslashes escapes the reference.
func expandNpmConfig(config npmConfig, env map[string]string) npmConfig {
	replace := func(text string) string {
		return npmEnvironmentReference.ReplaceAllStringFunc(text, func(match string) string {
			parts := npmEnvironmentReference.FindStringSubmatch(match)
			escapes, name, optional := parts[1], parts[2], parts[3] != ""
			if len(escapes)%2 == 1 {
				return match[(len(escapes)+1)/2:]
			}
			value, found := env[name]
			if !found {
				value = "${" + name + "}"
				if optional {
					value = ""
				}
			}
			return escapes[len(escapes)/2:] + value
		})
	}
	expanded := make(npmConfig, len(config))
	for key, values := range config {
		replaced := make([]string, len(values))
		for index, value := range values {
			replaced[index] = replace(value)
		}
		expanded[replace(key)] = replaced
	}
	return expanded
}

func lookupEnvironment(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		env[key] = value
	}
	return env
}

func lastValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func optionConfig(options []npmOption) npmConfig {
	config := npmConfig{}
	for _, option := range options {
		config[option.name] = append(config[option.name], option.value)
	}
	return config
}

// environmentConfig mirrors npm's environment layer: npm_config_ names are
// case-insensitive, underscores after the first character become dashes,
// empty values are ignored, and the last variant in the environment wins.
func environmentConfig(environ []string) npmConfig {
	config := npmConfig{}
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		if len(key) <= len("npm_config_") || !strings.EqualFold(key[:len("npm_config_")], "npm_config_") || value == "" {
			continue
		}
		name := key[len("npm_config_"):]
		if strings.HasPrefix(name, "//") {
			continue
		}
		name = strings.ToLower(name[:1] + strings.ReplaceAll(name[1:], "_", "-"))
		config[name] = []string{value}
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
