// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// berrySettings is the configuration Yarn 4 would use for one command before
// SCFW overrides it. Yarn 4 ignores the standard proxy variables.
type berrySettings struct {
	// HTTPS and HTTP are httpsProxy and httpProxy; neither covers the other.
	HTTPS, HTTP string
}

// berryRC is one .yarnrc.yml file, and dir the directory relative paths in it
// are resolved against.
type berryRC struct {
	dir  string
	data map[string]any
}

// networkFields are the per-host settings that would route around SCFW or
// make Yarn reject its certificate; environment variables cannot override them.
var networkFields = []string{"httpsProxy", "httpProxy", "httpsCaFilePath", "httpsCertFilePath", "httpsKeyFilePath"}

func (yarn Yarn) berrySettings(command []string) (berrySettings, error) {
	environ := os.Environ()
	env := nodeproxy.LookupEnvironment(environ)
	_, _, cwd := parseYarnCommand(berry, command)
	dir, err := os.Getwd()
	if err != nil {
		return berrySettings{}, errors.New("could not resolve yarn directory")
	}
	if cwd != "" {
		dir = filepath.Join(dir, cwd)
		if filepath.IsAbs(cwd) {
			dir = filepath.Clean(cwd)
		}
	}
	rcs, err := readBerryConfig(dir, environ, env)
	if err != nil {
		return berrySettings{}, err
	}
	for _, rc := range rcs {
		settings, _ := rc.data["networkSettings"].(map[string]any)
		globs := make([]string, 0, len(settings))
		for glob := range settings {
			globs = append(globs, glob)
		}
		slices.Sort(globs)
		for _, glob := range globs {
			entry, _ := settings[glob].(map[string]any)
			for _, field := range networkFields {
				if entry[field] != nil {
					return berrySettings{}, fmt.Errorf("yarn networkSettings for %q set a per-host proxy, CA, or client certificate, which SCFW cannot route; configure a top-level httpsProxy/httpsCaFilePath or YARN_HTTPS_PROXY instead", glob)
				}
			}
		}
	}
	get := func(key string) string {
		for _, rc := range rcs {
			if value, found := rc.data[key]; found && value != nil {
				return fmt.Sprint(value)
			}
		}
		return ""
	}
	if get("httpsCertFilePath") != "" || get("httpsKeyFilePath") != "" {
		return berrySettings{}, errors.New("yarn client certificates (httpsCertFilePath/httpsKeyFilePath) are not supported through SCFW")
	}
	return berrySettings{HTTPS: get("httpsProxy"), HTTP: get("httpProxy")}, nil
}

// readBerryConfig returns Yarn 4's settings, highest precedence first: YARN_*
// variables, then the rc files from dir up to the root, then ~/.yarnrc.yml.
// YARN_RC_FILENAME renames the project files but not the home file.
func readBerryConfig(dir string, environ []string, env map[string]string) ([]berryRC, error) {
	rcs := []berryRC{{dir: dir, data: berryEnvironmentConfig(environ)}}
	name := ".yarnrc.yml"
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		if strings.EqualFold(key, "YARN_RC_FILENAME") && value != "" {
			name = value
		}
	}
	var paths []string
	for current := dir; ; current = filepath.Dir(current) {
		paths = append(paths, filepath.Join(current, name))
		if filepath.Dir(current) == current {
			break
		}
	}
	if home := env["HOME"]; home != "" && !slices.Contains(paths, filepath.Join(home, ".yarnrc.yml")) {
		paths = append(paths, filepath.Join(home, ".yarnrc.yml"))
	}
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		data, err := nodeproxy.ReadConfigFile(path)
		if err != nil {
			return nil, errors.New("could not read yarn configuration")
		}
		var parsed map[string]any
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			return nil, errors.New("could not read yarn configuration")
		}
		interpolated, err := interpolate(parsed, env)
		if err != nil {
			return nil, err
		}
		values, _ := interpolated.(map[string]any)
		rcs = append(rcs, berryRC{dir: filepath.Dir(path), data: values})
	}
	return rcs, nil
}

// berryEnvironmentConfig maps YARN_<SNAKE_NAME>, matched case-insensitively,
// to the camelCase setting it overrides.
func berryEnvironmentConfig(environ []string) map[string]any {
	config := map[string]any{}
	for _, item := range environ {
		key, value, _ := strings.Cut(item, "=")
		name, found := strings.CutPrefix(strings.ToLower(key), "yarn_")
		if !found || name == "" || value == "" {
			continue
		}
		words := strings.Split(name, "_")
		for index := 1; index < len(words); index++ {
			if words[index] != "" {
				words[index] = strings.ToUpper(words[index][:1]) + words[index][1:]
			}
		}
		config[strings.Join(words, "")] = value
	}
	return config
}

var berryReference = regexp.MustCompile(`\$\{([a-zA-Z]\w*)(?:(:-|-)([^}]*))?\}`)

// interpolate applies Yarn's ${NAME}, ${NAME:-fallback}, and ${NAME-fallback}
// substitution to every string value; an unset ${NAME} is an error, as in Yarn.
func interpolate(value any, env map[string]string) (any, error) {
	switch typed := value.(type) {
	case string:
		var missing bool
		result := berryReference.ReplaceAllStringFunc(typed, func(match string) string {
			parts := berryReference.FindStringSubmatch(match)
			variable, found := env[parts[1]]
			switch {
			case parts[2] == ":-" && (!found || variable == ""), parts[2] == "-" && !found:
				return parts[3]
			case !found:
				missing = true
			}
			return variable
		})
		if missing {
			return nil, errors.New("yarn configuration references an unset environment variable")
		}
		return result, nil
	case map[string]any:
		for key, item := range typed {
			replaced, err := interpolate(item, env)
			if err != nil {
				return nil, err
			}
			typed[key] = replaced
		}
	case []any:
		for index, item := range typed {
			replaced, err := interpolate(item, env)
			if err != nil {
				return nil, err
			}
			typed[index] = replaced
		}
	}
	return value, nil
}
