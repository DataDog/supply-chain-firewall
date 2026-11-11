// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// classicSettings is the configuration Yarn Classic would use for one command
// before SCFW overrides it.
type classicSettings struct {
	// HTTPS and HTTP are the upstream proxies Yarn would use for each scheme.
	HTTPS, HTTP string
	// NoProxy applies only to proxies taken from the standard variables:
	// Yarn passes a configured proxy to its HTTP client, which then ignores it.
	NoProxy string
	// CAFile wins over CA, as in Yarn's request manager.
	CAFile     string
	CA         []string
	StrictSSL  bool
	Registries []string
}

// classicConfig holds Yarn Classic's configuration layers, highest first.
// Command options win when non-empty; otherwise the first Yarn layer that sets
// a key decides, and npm layers are read only when no Yarn layer sets it.
type classicConfig struct {
	options, yarn, npm []nodeproxy.Config
	// rcArgProxy records an rc-arg proxy for any command, which a `yarn
	// workspace` child would apply over SCFW's environment.
	rcArgProxy bool
}

func (config classicConfig) get(key string) string {
	return nodeproxy.LastValue(config.values(key))
}

func (config classicConfig) values(key string) []string {
	for _, layer := range config.options {
		if nodeproxy.LastValue(layer[key]) != "" {
			return layer[key]
		}
	}
	for _, layers := range [][]nodeproxy.Config{config.yarn, config.npm} {
		if values, found := firstLayer(layers, key); found {
			return values
		}
	}
	return nil
}

func firstLayer(layers []nodeproxy.Config, key string) ([]string, bool) {
	for _, layer := range layers {
		if values, found := layer[key]; found {
			return values, true
		}
	}
	return nil, false
}

func (yarn Yarn) classicSettings(command []string) (classicSettings, error) {
	environ := os.Environ()
	env := nodeproxy.LookupEnvironment(environ)
	config, err := readClassicConfig(command, environ, env)
	if err != nil {
		return classicSettings{}, err
	}
	// `yarn workspace` re-runs Yarn without the command options SCFW adds, and
	// .yarnrc rc-args win over the environment SCFW sets for that child.
	if cmd, _, _ := parseYarnCommand(classic, command); cmd.name == "workspace" && config.rcArgProxy {
		return classicSettings{}, errors.New("yarn workspace commands cannot be routed through SCFW when a .yarnrc sets --proxy or --https-proxy; run the command in the workspace directory instead")
	}
	var settings classicSettings
	fromEnvironment := false
	environmentProxy := func(names ...string) string {
		for _, name := range names {
			if value := env[name]; value != "" {
				fromEnvironment = true
				return value
			}
		}
		return ""
	}
	// An empty proxy falls back to the standard variables and false disables
	// that fallback; an unset https-proxy uses proxy.
	httpProxy, httpsProxy := config.get("proxy"), config.get("https-proxy")
	switch httpProxy {
	case "false":
	case "":
		settings.HTTP = environmentProxy("HTTP_PROXY", "http_proxy")
	default:
		settings.HTTP = httpProxy
	}
	if httpsProxy == "" && httpProxy != "false" {
		httpsProxy = httpProxy
	}
	switch httpsProxy {
	case "false":
	case "":
		settings.HTTPS = environmentProxy("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	default:
		settings.HTTPS = httpsProxy
	}
	if fromEnvironment {
		settings.NoProxy = env["NO_PROXY"]
		if settings.NoProxy == "" {
			settings.NoProxy = env["no_proxy"]
		}
	}

	settings.CAFile = expandHome(config.get("cafile"), env["HOME"])
	if settings.CAFile == "" {
		settings.CA = config.values("ca")
	}
	// Yarn's default strict-ssl shadows npm's, so only Yarn layers count.
	yarnOnly := classicConfig{options: config.options, yarn: config.yarn}
	settings.StrictSSL = yarnOnly.get("strict-ssl") != "false"

	// Tarballs may come from any registry Yarn knows, including npm's own
	// registry setting, which Yarn uses for metadata.
	settings.Registries = []string{config.get("registry")}
	if settings.Registries[0] == "" {
		settings.Registries[0] = "https://registry.yarnpkg.com"
	}
	if values, found := firstLayer(config.npm, "registry"); found {
		settings.Registries = append(settings.Registries, nodeproxy.LastValue(values))
	}
	var scopes []string
	for _, layer := range slices.Concat(config.options, config.yarn, config.npm) {
		for key := range layer {
			if strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry") && !slices.Contains(scopes, key) {
				scopes = append(scopes, key)
			}
		}
	}
	slices.Sort(scopes)
	for _, key := range scopes {
		settings.Registries = append(settings.Registries, config.get(key))
	}
	return settings, nil
}

// expandHome resolves a path setting like Yarn: a leading ~ is the home
// directory and relative paths are relative to cwd.
func expandHome(value, home string) string {
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

// readClassicConfig mirrors Yarn 1.22: command options; .yarnrc "--" lines
// (rc-args); yarn_* variables; .yarnrc in the cwd, home, and global prefix,
// then parent directories; npm_config_* variables; and .npmrc in the same order.
func readClassicConfig(command, environ []string, env map[string]string) (classicConfig, error) {
	cmd, _, cwd := parseYarnCommand(classic, command)
	dir, err := os.Getwd()
	if err != nil {
		return classicConfig{}, errors.New("could not resolve yarn directory")
	}
	if cwd != "" {
		dir = filepath.Join(dir, cwd)
		if filepath.IsAbs(cwd) {
			dir = filepath.Clean(cwd)
		}
	}
	home, prefix := env["HOME"], nodeproxy.GlobalPrefix(env)
	name := cmd.name
	if name == "" {
		name = "install"
	}

	var rcFiles []string
	for current := dir; ; current = filepath.Dir(current) {
		rcFiles = append(rcFiles, filepath.Join(current, ".yarnrc"))
		if filepath.Dir(current) == current {
			break
		}
	}
	slices.Reverse(rcFiles)
	rcFiles = append(rcFiles, "/etc/yarn/config", "/etc/yarnrc")
	if home != "" {
		rcFiles = append(rcFiles, filepath.Join(home, ".config", "yarn", "config"), filepath.Join(home, ".config", "yarn"),
			filepath.Join(home, ".yarn", "config"), filepath.Join(home, ".yarnrc"))
	}
	if env["YARN_CONFIG"] != "" {
		rcFiles = append(rcFiles, env["YARN_CONFIG"])
	}
	rcArgs := nodeproxy.Config{}
	rcArgProxy := false
	for _, path := range rcFiles {
		layer, err := readYarnrc(path)
		if err != nil {
			return classicConfig{}, err
		}
		// Later files win; "--<command>.<flag>" applies to that command only.
		for key, values := range layer {
			match := rcArgPattern.FindStringSubmatch(key)
			if match != nil && (match[1] == "" || match[1] == name) {
				rcArgs[match[2]] = values
			}
			if match != nil && (match[2] == "proxy" || match[2] == "https-proxy") {
				rcArgProxy = true
			}
		}
	}

	config := classicConfig{options: []nodeproxy.Config{classicOptions(command), rcArgs}, rcArgProxy: rcArgProxy}
	config.yarn = []nodeproxy.Config{yarnEnvironmentConfig(environ)}
	for _, path := range configLocations(dir, ".yarnrc", filepath.Join(home, ".yarnrc"), filepath.Join(prefix, "etc", "yarnrc")) {
		layer, err := readYarnrc(path)
		if err != nil {
			return classicConfig{}, err
		}
		config.yarn = append(config.yarn, layer)
	}
	npmEnvironment := nodeproxy.EnvironmentConfig(environ)
	userconfig := nodeproxy.LastValue(npmEnvironment["userconfig"])
	if userconfig == "" {
		userconfig = filepath.Join(home, ".npmrc")
	}
	config.npm = []nodeproxy.Config{npmEnvironment}
	for _, path := range configLocations(dir, ".npmrc", userconfig, filepath.Join(prefix, "etc", "npmrc")) {
		layer, err := nodeproxy.LoadNpmrc(path, env)
		if err != nil {
			return classicConfig{}, err
		}
		config.npm = append(config.npm, layer)
	}
	return config, nil
}

var rcArgPattern = regexp.MustCompile(`^--(?:([^.]+)\.)?(.*)$`)

// configLocations lists Yarn's rc files, highest precedence first: the cwd,
// the user and global files, then every parent directory except the root.
func configLocations(dir, name, user, global string) []string {
	locations := []string{filepath.Join(dir, name), user, global}
	for current := filepath.Dir(dir); filepath.Dir(current) != current; current = filepath.Dir(current) {
		locations = append(locations, filepath.Join(current, name))
	}
	return locations
}

// classicOptions reads the proxy and registry options Yarn accepts anywhere
// before "--".
func classicOptions(command []string) nodeproxy.Config {
	config := nodeproxy.Config{}
	for index := 0; index < len(command) && command[index] != "--"; index++ {
		name, value, assigned := strings.Cut(command[index], "=")
		if name != "--proxy" && name != "--https-proxy" && name != "--registry" {
			continue
		}
		if !assigned {
			if index+1 >= len(command) {
				break
			}
			index++
			value = command[index]
		}
		config[strings.TrimPrefix(name, "--")] = []string{value}
	}
	return config
}

// yarnEnvironmentConfig mirrors Yarn's yarn_ environment layer: names are
// case-insensitive, "__" becomes "." and "_" becomes "-", and later entries win.
func yarnEnvironmentConfig(environ []string) nodeproxy.Config {
	config := nodeproxy.Config{}
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		name, found := strings.CutPrefix(strings.ToLower(key), "yarn_")
		if !found || name == "" {
			continue
		}
		name = underscorePattern.ReplaceAllString(strings.ReplaceAll(name, "__", "."), "$1-")
		config[name] = []string{value}
	}
	return config
}

var underscorePattern = regexp.MustCompile(`([^_])_`)

// readYarnrc reads a Classic .yarnrc: "key value" lines whose key and value
// may be JSON strings. A missing or unreadable file is an empty layer.
func readYarnrc(path string) (nodeproxy.Config, error) {
	// Yarn skips directories, such as ~/.config/yarn, among its rc locations.
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nodeproxy.Config{}, nil
	}
	data, err := nodeproxy.ReadConfigFile(path)
	if os.IsNotExist(err) || os.IsPermission(err) || errors.Is(err, syscall.ENOTDIR) {
		return nodeproxy.Config{}, nil
	}
	if err != nil {
		return nil, errors.New("could not read yarn configuration")
	}
	config := nodeproxy.Config{}
	for _, line := range strings.FieldsFunc(string(data), func(r rune) bool { return r == '\r' || r == '\n' }) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, rest := yarnrcToken(line)
		if key == "" {
			continue
		}
		value, _ := yarnrcToken(strings.TrimSpace(rest))
		config[strings.TrimSuffix(key, ":")] = []string{value}
	}
	return config, nil
}

// yarnrcToken splits a leading JSON string or bare word from text.
func yarnrcToken(text string) (token, rest string) {
	if strings.HasPrefix(text, `"`) {
		decoder := json.NewDecoder(strings.NewReader(text))
		if decoder.Decode(&token) == nil {
			return token, text[decoder.InputOffset():]
		}
	}
	if index := strings.IndexAny(text, " \t"); index >= 0 {
		return text[:index], text[index:]
	}
	return text, ""
}
