// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// pipDiscoveryResult holds effective process settings and explicit source URLs.
// Requirements files and pip caches remain the package manager's responsibility.
type pipDiscoveryResult struct {
	Cert, ClientCert                                  string
	TrustedHosts                                      []string
	HTTP, HTTPS, FallbackHTTP, FallbackHTTPS, NoProxy string
	LooseNoProxy                                      bool
	SystemProxyBypass                                 func(*url.URL) bool
	Indexes, Direct, Links                            []string
}

var errPipConfiguration = errors.New("invalid pip configuration")

func (pip Pip) settings(args []string) (pipDiscoveryResult, error) {
	version := pip.version
	if version == (pm.Version{}) && pip.versionErr != nil {
		return pipDiscoveryResult{}, errors.New("could not determine pip proxy compatibility")
	}
	if version == (pm.Version{}) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var err error
		version, err = resolvePipVersion(ctx, pip.executable)
		if err != nil {
			return pipDiscoveryResult{}, errors.New("could not determine pip proxy compatibility")
		}
	}

	options, targets := parsePipOptions(args)
	command := ""
	if len(targets) > 0 {
		command = targets[0]
	}
	isolated := false
	python := ""
	pythonSpecified := false
	for _, option := range options {
		if option.name == "isolated" {
			isolated = true
		}
		if option.name == "python" {
			python = option.value
			pythonSpecified = true
		}
	}
	// Pip's main parser resolves --python (including configuration/environment)
	// before it creates the command parser in the selected interpreter prefix.
	prefix, err := pip.installationPrefix("")
	if err != nil {
		return pipDiscoveryResult{}, err
	}
	general, err := readPipConfig(prefix, "", false, version)
	if errors.Is(err, errPipConfiguration) {
		return pipDiscoveryResult{}, nil
	}
	if err != nil {
		return pipDiscoveryResult{}, err
	}
	if !pythonSpecified && !version.LessThan(pm.Version{Major: 22, Minor: 3}) {
		python = general["python"]
	}
	if python != "" {
		prefix, err = pip.installationPrefix(python)
		if err != nil {
			return pipDiscoveryResult{}, err
		}
	}

	values, err := readPipConfig(prefix, command, isolated, version)
	if errors.Is(err, errPipConfiguration) {
		return pipDiscoveryResult{}, nil
	} // Let pip print its own configuration error and exit code.
	if err != nil {
		return pipDiscoveryResult{}, err
	}
	lists := map[string][]string{
		"trusted-host":    strings.Fields(values["trusted-host"]),
		"extra-index-url": strings.Fields(values["extra-index-url"]),
		"find-links":      strings.Fields(values["find-links"]),
	}
	for _, option := range options {
		if _, multiple := lists[option.name]; multiple {
			lists[option.name] = append(lists[option.name], option.value)
		} else {
			values[option.name] = option.value
		}
	}
	result := pipDiscoveryResult{Cert: values["cert"], ClientCert: values["client-cert"], TrustedHosts: lists["trusted-host"], Indexes: append([]string{values["index-url"]}, lists["extra-index-url"]...), Links: lists["find-links"]}

	// pip 26.2 vendors Requests 2.34, which changed NO_PROXY to domain-boundary matching.
	result.LooseNoProxy = version.LessThan(pm.Version{Major: 26, Minor: 2})
	explicit, hasProxy := values["proxy"]
	trustEnvironment := version.LessThan(pm.Version{Major: 26, Minor: 2}) || (!hasProxy && !pipBoolean(values["no-proxy-env"]))
	result.HTTP, result.HTTPS = explicit, explicit
	result.FallbackHTTP, result.FallbackHTTPS = explicit, explicit
	if trustEnvironment {
		discovery, err := pipProxies(readSystemProxies)
		if err != nil {
			return pipDiscoveryResult{}, err
		}
		proxies := discovery.proxies
		result.SystemProxyBypass = discovery.bypasses
		if value, ok := proxies["http"]; ok {
			result.HTTP = value
		} else if value, ok := proxies["all"]; ok {
			result.HTTP = value
		}
		if value, ok := proxies["https"]; ok {
			result.HTTPS = value
		} else if value, ok := proxies["all"]; ok {
			result.HTTPS = value
		}
		result.NoProxy = proxies["no"]
		if value := os.Getenv("REQUESTS_CA_BUNDLE"); value != "" {
			result.Cert = value
		} else if value := os.Getenv("CURL_CA_BUNDLE"); value != "" {
			result.Cert = value
		}
	} else if explicit == "" {
		result.FallbackHTTP, result.FallbackHTTPS = "", ""
	}
	for _, target := range append(targets, strings.Fields(values["editable"])...) {
		collectDirectURL(target, &result)
	}
	return result, nil
}

func pipBoolean(value string) bool {
	return slices.Contains([]string{"1", "true", "yes", "on", "y", "t"}, strings.ToLower(value))
}

func pipEnvironmentProxies() map[string]string {
	proxies := map[string]string{}
	for _, item := range os.Environ() {
		key, value, _ := strings.Cut(item, "=")
		if strings.HasSuffix(strings.ToLower(key), "_proxy") && value != "" {
			proxies[strings.TrimSuffix(strings.ToLower(key), "_proxy")] = value
		}
	}
	if os.Getenv("REQUEST_METHOD") != "" {
		delete(proxies, "http")
	}
	for _, item := range os.Environ() {
		key, value, _ := strings.Cut(item, "=")
		if key == strings.ToLower(key) && strings.HasSuffix(key, "_proxy") {
			key = strings.TrimSuffix(key, "_proxy")
			if value == "" {
				delete(proxies, key)
			} else {
				proxies[key] = value
			}
		}
	}
	return proxies
}

func expandPipPath(value string) string {
	if value == "" {
		return ""
	}
	if value == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
	}
	if strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	absolute, err := filepath.Abs(value)
	if err == nil {
		return absolute
	}
	return value
}

func (pip Pip) installationPrefix(target string) (string, error) {
	interpreter := target
	if interpreter == "" {
		var err error
		interpreter, err = pip.interpreter()
		if err != nil {
			return "", err
		}
	}
	if info, err := os.Stat(interpreter); err == nil && info.IsDir() {
		return expandPipPath(interpreter), nil
	}
	// A venv's Python is normally a symlink: inspect its original prefix before
	// resolving it, so a non-activated venv still selects its site config.
	prefix := filepath.Dir(filepath.Dir(expandPipPath(interpreter)))
	if _, err := os.Stat(filepath.Join(prefix, "pyvenv.cfg")); err == nil {
		return prefix, nil
	}
	if resolved, err := filepath.EvalSymlinks(interpreter); err == nil {
		prefix = filepath.Dir(filepath.Dir(resolved))
	}
	return prefix, nil
}

// Resolve the same files and precedence as pip's RawConfigParser configuration:
// global files, user files, installation/venv, PIP_CONFIG_FILE, then environment.
// Merge each section across files before applying [global], the active command
// section, and environment overrides, matching pip's section precedence.
func readPipConfig(prefix, command string, isolated bool, versions ...pm.Version) (map[string]string, error) {
	version := pm.Version{Major: 26, Minor: 2}
	if len(versions) > 0 {
		version = versions[0]
	}
	home, _ := os.UserHomeDir()
	globalDirs := strings.Split(os.Getenv("XDG_CONFIG_DIRS"), string(os.PathListSeparator))
	if len(globalDirs) == 1 && globalDirs[0] == "" {
		globalDirs = []string{"/etc/xdg"}
	}
	userDir := os.Getenv("XDG_CONFIG_HOME")
	if userDir == "" {
		userDir = filepath.Join(home, ".config")
	}
	var files []string
	if runtime.GOOS == "darwin" {
		userDir = filepath.Join(home, ".config")
		globalDirs = []string{"/Library/Application Support"}
		if !version.LessThan(pm.Version{Major: 26, Minor: 2}) {
			globalDirs = strings.Split(os.Getenv("XDG_DATA_DIRS"), string(os.PathListSeparator))
		}
		if len(globalDirs) == 1 && globalDirs[0] == "" {
			globalDirs = []string{"/Library/Application Support"}
		}
		userData := ""
		if !version.LessThan(pm.Version{Major: 26, Minor: 2}) {
			userData = os.Getenv("XDG_DATA_HOME")
		}
		if userData == "" {
			userData = filepath.Join(home, "Library", "Application Support")
		}
		if info, err := os.Stat(filepath.Join(userData, "pip")); err == nil && info.IsDir() {
			userDir = userData
		}
	}
	for _, directory := range globalDirs {
		if directory != "" {
			files = append(files, filepath.Join(directory, "pip", "pip.conf"))
		}
	}
	if runtime.GOOS != "darwin" {
		files = append(files, "/etc/pip.conf")
	}
	envConfig, envPresent := os.LookupEnv("PIP_CONFIG_FILE")
	_, envExists := os.Stat(envConfig)
	if !isolated && (envConfig == "" || envExists != nil) {
		files = append(files, filepath.Join(home, ".pip", "pip.conf"), filepath.Join(userDir, "pip", "pip.conf"))
	}
	files = append(files, filepath.Join(prefix, "pip.conf"))
	if envPresent {
		files = append(files, envConfig)
	}
	if envConfig == os.DevNull {
		files = nil
	}
	sections := map[string]map[string]string{}
	for _, file := range files {
		data, err := readPipConfigFile(file)
		if os.IsNotExist(err) || os.IsPermission(err) || file == "" {
			continue
		}
		if err != nil {
			return nil, errors.New("could not read pip configuration")
		}
		parsed, err := parsePipINI(data)
		if err != nil {
			return nil, err
		}
		for _, section := range []string{"global", command} {
			if sections[section] == nil {
				sections[section] = map[string]string{}
			}
			for key, value := range parsed[section] {
				sections[section][key] = value
			}
		}
	}
	values := map[string]string{"index-url": pypi.DefaultIndexURL}
	for _, section := range []string{"global", command} {
		for key, value := range sections[section] {
			if value != "" {
				values[key] = value
			}
		}
	}
	if !isolated {
		for _, item := range os.Environ() {
			key, value, _ := strings.Cut(item, "=")
			if strings.HasPrefix(key, "PIP_") && value != "" {
				values[canonicalPipOption(key[4:])] = value
			}
		}
	}
	return values, nil
}

func parsePipINI(data []byte) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	rawKeys := map[string]map[string]bool{}
	section, key := "", ""
	indent := -1
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxPipConfigBytes)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		depth := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if section != "" && key != "" && depth > indent {
			sections[section][key] += "\n" + line
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			section = line[1:strings.Index(line, "]")]
			key = ""
			if sections[section] != nil {
				return nil, errPipConfiguration
			}
			sections[section] = map[string]string{}
			rawKeys[section] = map[string]bool{}
			continue
		}
		delimiter := strings.IndexAny(line, "=:")
		if section == "" || delimiter < 0 {
			return nil, errPipConfiguration
		}
		rawKey := strings.ToLower(strings.TrimSpace(line[:delimiter]))
		if rawKeys[section][rawKey] {
			return nil, errPipConfiguration
		}
		rawKeys[section][rawKey] = true
		key = canonicalPipOption(rawKey)

		sections[section][key] = strings.TrimSpace(line[delimiter+1:])
		indent = depth
	}
	if scanner.Err() != nil {
		return nil, errPipConfiguration
	}
	for section, entries := range sections {
		if section != "DEFAULT" {
			for key, value := range sections["DEFAULT"] {
				if _, exists := entries[key]; !exists {
					entries[key] = value
				}
			}
		}
	}
	return sections, nil
}

const maxPipConfigBytes = 8 << 20

func readPipConfigFile(path string) ([]byte, error) {
	if path == os.DevNull {
		return nil, nil
	}
	// Nonblocking open plus a regular-file check also handles a path swapped
	// for a FIFO while discovery is reading it.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("pip configuration requires a regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxPipConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPipConfigBytes {
		return nil, errors.New("pip configuration is too large")
	}
	return body, nil
}

var namedDirectURL = regexp.MustCompile(`(?i)^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?\s*@\s*(https?://\S+)`)

func collectDirectURL(requirement string, result *pipDiscoveryResult) {
	value := strings.TrimSpace(requirement)
	marker := ";"
	if strings.HasPrefix(strings.ToLower(value), "http://") || strings.HasPrefix(strings.ToLower(value), "https://") {
		marker = "; "
	}
	if before, _, found := strings.Cut(value, marker); found {
		value = strings.TrimSpace(before)
	}
	if match := namedDirectURL.FindStringSubmatch(value); len(match) == 2 {
		value = match[1]
	} else if !strings.HasPrefix(strings.ToLower(value), "http://") && !strings.HasPrefix(strings.ToLower(value), "https://") {
		return
	}
	if index := strings.IndexFunc(value, unicode.IsSpace); index >= 0 {
		value = value[:index]
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		result.Direct = append(result.Direct, value)
	}
}
