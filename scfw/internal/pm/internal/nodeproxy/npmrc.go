// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package nodeproxy reads configuration shared by Node package-manager adapters.
package nodeproxy

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Config maps an npm configuration key to its values within one layer; a
// scalar setting uses its last value.
type Config map[string][]string

// LoadNpmrc reads one npmrc file. A missing or unreadable file is an empty
// layer, as in npm.
func LoadNpmrc(path string, env map[string]string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	data, err := ReadConfigFile(path)
	if os.IsNotExist(err) || os.IsPermission(err) || errors.Is(err, syscall.ENOTDIR) {
		return Config{}, nil
	}
	if err != nil {
		return nil, errors.New("could not read npm configuration")
	}
	return ParseNpmrc(data, env), nil
}

const maxNpmrcBytes = 8 << 20

// ReadConfigFile reads a bounded, regular configuration file.
func ReadConfigFile(path string) ([]byte, error) {
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

// ParseNpmrc parses an npmrc file as npm's ini package does. Keys inside a
// [section] are not top-level settings, so npm ignores them.
func ParseNpmrc(data []byte, env map[string]string) Config {
	config := Config{}
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
	return ExpandConfig(config, env)
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

// ExpandConfig applies npm's ${VAR} substitution to keys and values. An
// unset variable stays literal unless written ${VAR?}; an odd number of
// preceding backslashes escapes the reference.
func ExpandConfig(config Config, env map[string]string) Config {
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
	expanded := make(Config, len(config))
	for key, values := range config {
		replaced := make([]string, len(values))
		for index, value := range values {
			replaced[index] = replace(value)
		}
		expanded[replace(key)] = replaced
	}
	return expanded
}

// EnvironmentConfig mirrors npm's environment layer: npm_config_ names are
// case-insensitive, underscores after the first character become dashes,
// empty values are ignored, and the last variant in the environment wins.
func EnvironmentConfig(environ []string) Config {
	config := Config{}
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

// LookupEnvironment indexes environ by exact key.
func LookupEnvironment(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		env[key] = value
	}
	return env
}

// LastValue returns a scalar setting's effective value.
func LastValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

// GlobalPrefix mirrors npm's default global prefix on Unix: PREFIX, else the
// directory above the bin directory of the node executable npm runs on.
func GlobalPrefix(env map[string]string) string {
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
