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
	// NoProxy is the standard variables' bypass list. It applies only to a
	// scheme whose proxy came from those variables: Yarn passes a configured
	// proxy to its HTTP client, which then ignores NO_PROXY for it.
	NoProxy                   string
	NoProxyHTTP, NoProxyHTTPS bool
	// A readable CAFile wins over CA; when Yarn cannot read the file it
	// keeps CA, as in its request manager.
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
	// dir is the Yarn process directory, which relative paths resolve against.
	dir string
}

func (config classicConfig) get(key string) string {
	return nodeproxy.LastValue(config.values(key))
}

func (config classicConfig) values(key string) []string {
	values, _ := config.source(key)
	return values
}

// source returns a key's values and whether they come from an .npmrc file.
func (config classicConfig) source(key string) ([]string, bool) {
	for _, layer := range config.options {
		if nodeproxy.LastValue(layer[key]) != "" {
			return layer[key], false
		}
	}
	if values, found := firstLayer(config.yarn, key); found {
		return values, false
	}
	// The first npm layer holds the npm_config_ variables.
	for index, layer := range config.npm {
		if values, found := layer[key]; found {
			return values, index > 0
		}
	}
	return nil, false
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
	var settings classicSettings
	environmentProxy := func(names ...string) string {
		for _, name := range names {
			if value := env[name]; value != "" {
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
		settings.NoProxyHTTP = settings.HTTP != ""
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
		settings.NoProxyHTTPS = settings.HTTPS != ""
	default:
		settings.HTTPS = httpsProxy
	}
	if settings.NoProxyHTTP || settings.NoProxyHTTPS {
		settings.NoProxy = env["NO_PROXY"]
		if settings.NoProxy == "" {
			settings.NoProxy = env["no_proxy"]
		}
	}

	cafile, npmrc := config.source("cafile")
	settings.CAFile = classicCAFile(nodeproxy.LastValue(cafile), npmrc, env["HOME"], config.dir)
	settings.CA = config.values("ca")
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

// classicCAFile resolves cafile as Yarn does: relative to the Yarn process
// directory, which is not --cwd, and with a leading ~/ for the home directory
// only in .npmrc files, which Yarn normalizes as npm path options.
func classicCAFile(value string, npmrc bool, home, dir string) string {
	if value == "" {
		return ""
	}
	if rest, found := strings.CutPrefix(value, "~/"); npmrc && found {
		return filepath.Join(home, rest)
	}
	return resolvePath(dir, value)
}

// resolvePath resolves path against dir, as Node's path.resolve does.
func resolvePath(dir, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, path)
}

// classicProcess is how one Yarn Classic process starts: the directory it
// runs in, its arguments, and the configuration directories they select.
type classicProcess struct {
	dir     string
	command []string
	cmd     yarnCommand
	// own holds the arguments Yarn parses itself.
	own []string
	// rcArgs holds the .yarnrc "--" lines that apply, as option and value pairs.
	rcArgs []string
	// project is the absolute directory Yarn reads its configuration files
	// and workspace root from.
	project string
}

func newClassicProcess(dir string, command []string, env map[string]string) (classicProcess, error) {
	cmd, _, _ := parseYarnCommand(classic, command)
	process := classicProcess{dir: dir, command: command, cmd: cmd, own: classicOwnArguments(command, cmd)}
	name := cmd.name
	if name == "" {
		name = "install"
	}
	var err error
	if process.rcArgs, err = classicRCArgs(dir, name, process.own, env, nil); err != nil {
		return classicProcess{}, err
	}
	// Command-line options are parsed after rc-args, and the last --cwd wins.
	cwd := dir
	for _, arguments := range [][]string{process.rcArgs, process.own} {
		if values := optionValues(arguments, "--cwd"); len(values) > 0 {
			cwd = values[len(values)-1]
		}
	}
	process.project = classicProjectRoot(dir, cwd)
	return process, nil
}

// classicProjectRoot mirrors Yarn's findProjectRoot: the nearest directory at
// or above cwd with a package.json, else cwd. A relative cwd is walked as
// written, so the walk stops at the process directory, as in Yarn.
func classicProjectRoot(dir, cwd string) string {
	for current := cwd; ; current = filepath.Dir(current) {
		if info, err := os.Stat(filepath.Join(resolvePath(dir, current), "package.json")); err == nil && !info.IsDir() {
			return resolvePath(dir, current)
		}
		if filepath.Dir(current) == current {
			return resolvePath(dir, cwd)
		}
	}
}

// classicRCArgs mirrors Yarn's getRcArgs: the "--" lines of the .yarnrc chain
// of the first exact --cwd in arguments, else of dir, plus --use-yarnrc files,
// for every command and then for name. An rc-arg --cwd, relative to its file,
// moves the chain and the rc-args are read again there; a cycle fails, as in
// Yarn.
func classicRCArgs(dir, name string, arguments []string, env map[string]string, previous []string) ([]string, error) {
	origin := firstExactCwd(arguments)
	if origin == "" {
		origin = dir
	}
	var files []string
	if !slices.Contains(arguments, "--no-default-rc") {
		files = classicRCFiles(origin, env["HOME"], env)
	}
	for index, argument := range arguments {
		if argument == "--use-yarnrc" && index+1 < len(arguments) && arguments[index+1] != "" && arguments[index+1][0] != '-' {
			files = append(files, arguments[index+1])
		}
	}
	merged := map[string]string{}
	for _, file := range files {
		file = resolvePath(dir, file)
		layer, err := readYarnrc(file)
		if err != nil {
			return nil, err
		}
		// Later files win.
		for key, values := range layer {
			if match := rcArgPattern.FindStringSubmatch(key); match != nil {
				if match[2] == "cwd" {
					values = []string{resolvePath(filepath.Dir(file), nodeproxy.LastValue(values))}
				}
				merged[key] = nodeproxy.LastValue(values)
			}
		}
	}
	var everyCommand, thisCommand []string
	for key := range merged {
		switch match := rcArgPattern.FindStringSubmatch(key); match[1] {
		case "":
			everyCommand = append(everyCommand, key)
		case name:
			thisCommand = append(thisCommand, key)
		}
	}
	slices.Sort(everyCommand)
	slices.Sort(thisCommand)
	var rcArgs []string
	for _, key := range slices.Concat(everyCommand, thisCommand) {
		rcArgs = append(rcArgs, "--"+rcArgPattern.FindStringSubmatch(key)[2], merged[key])
	}
	if cwd := firstExactCwd(rcArgs); cwd != "" && cwd != origin {
		if slices.Contains(previous, cwd) {
			return nil, errors.New("yarn .yarnrc files set --cwd recursively")
		}
		return classicRCArgs(dir, name, rcArgs, env, append(previous, origin))
	}
	return rcArgs, nil
}

// firstExactCwd returns the value after the first "--cwd" argument, the
// only form Yarn's rc-args lookup reads.
func firstExactCwd(arguments []string) string {
	if index := slices.Index(arguments, "--cwd"); index >= 0 && index+1 < len(arguments) {
		return arguments[index+1]
	}
	return ""
}

// optionValues returns the values of an option given as "name value" or
// "name=value", in order.
func optionValues(arguments []string, name string) []string {
	var values []string
	for index := 0; index < len(arguments); index++ {
		if value, found := strings.CutPrefix(arguments[index], name+"="); found {
			values = append(values, value)
		} else if arguments[index] == name && index+1 < len(arguments) {
			index++
			values = append(values, arguments[index])
		}
	}
	return values
}

// readClassicConfig mirrors Yarn 1.22: command options; .yarnrc "--" lines
// (rc-args); yarn_* variables; --use-yarnrc files; .yarnrc in the project,
// home, and global prefix, then parent directories; npm_config_* variables;
// and .npmrc in the same order. --no-default-rc drops the default files.
func readClassicConfig(command, environ []string, env map[string]string) (classicConfig, error) {
	dir, err := os.Getwd()
	if err != nil {
		return classicConfig{}, errors.New("could not resolve yarn directory")
	}
	// `yarn workspace` runs its command in the workspace, which is where the
	// configuration that applies is read from.
	process, _, err := classicTarget(dir, command, env)
	if err != nil {
		return classicConfig{}, err
	}
	home, prefix := env["HOME"], nodeproxy.GlobalPrefix(env)
	rcArgs := nodeproxy.Config{}
	for index := 0; index+1 < len(process.rcArgs); index += 2 {
		rcArgs[strings.TrimPrefix(process.rcArgs[index], "--")] = []string{process.rcArgs[index+1]}
	}
	config := classicConfig{options: []nodeproxy.Config{classicOptions(process.own), rcArgs}, dir: process.dir}
	config.yarn = []nodeproxy.Config{yarnEnvironmentConfig(environ)}
	// Yarn collects --use-yarnrc from rc-args and the command line; the last
	// file wins.
	yarnFiles := slices.Concat(optionValues(process.rcArgs, "--use-yarnrc"), optionValues(process.own, "--use-yarnrc"))
	slices.Reverse(yarnFiles)
	for index, file := range yarnFiles {
		yarnFiles[index] = resolvePath(process.dir, file)
	}
	defaultRC := !slices.Contains(process.rcArgs, "--no-default-rc") && !slices.Contains(process.own, "--no-default-rc")
	if defaultRC {
		yarnFiles = append(yarnFiles, configLocations(process.project, ".yarnrc", filepath.Join(home, ".yarnrc"), filepath.Join(prefix, "etc", "yarnrc"))...)
	}
	for _, path := range yarnFiles {
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
	if !defaultRC {
		return config, nil
	}
	for _, path := range configLocations(process.project, ".npmrc", userconfig, filepath.Join(prefix, "etc", "npmrc")) {
		layer, err := nodeproxy.LoadNpmrc(path, env)
		if err != nil {
			return classicConfig{}, err
		}
		config.npm = append(config.npm, layer)
	}
	return config, nil
}

// classicRCFiles lists the .yarnrc files Yarn merges for a process running in
// dir, in merge order: later files win. A relative dir is walked as written,
// as in Yarn.
func classicRCFiles(dir, home string, env map[string]string) []string {
	var files []string
	for current := dir; ; current = filepath.Dir(current) {
		files = append(files, filepath.Join(current, ".yarnrc"))
		if filepath.Dir(current) == current {
			break
		}
	}
	slices.Reverse(files)
	files = append(files, "/etc/yarn/config", "/etc/yarnrc")
	if home != "" {
		files = append(files, filepath.Join(home, ".config", "yarn", "config"), filepath.Join(home, ".config", "yarn"),
			filepath.Join(home, ".yarn", "config"), filepath.Join(home, ".yarnrc"))
	}
	if env["YARN_CONFIG"] != "" {
		files = append(files, env["YARN_CONFIG"])
	}
	return files
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

// classicOptions reads the proxy and registry options among the arguments
// Yarn parses itself.
func classicOptions(command []string) nodeproxy.Config {
	config := nodeproxy.Config{}
	for index := 0; index < len(command); index++ {
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
