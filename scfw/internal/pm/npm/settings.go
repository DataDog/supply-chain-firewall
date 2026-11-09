// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"os"
	"slices"
	"sort"
	"strings"
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
	layers := []npmConfig{optionConfig(parseNpmOptions(args)), environmentConfig(environ)}
	get := func(key string) []string {
		for _, layer := range layers {
			if values, found := layer[key]; found {
				return values
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
		CAFile:    scalar("cafile"),
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
