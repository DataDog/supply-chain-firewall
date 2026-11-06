// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type trustedHost struct {
	scheme, host string
	port         string
	wildcard     bool
}

func trustURL(settings map[string]any, command commandOptions) (func(*url.URL) bool, error) {
	var values []any
	if configured, exists := settings["allow-insecure-host"]; exists {
		var ok bool
		values, ok = configured.([]any)
		if !ok {
			return nil, errors.New("invalid uv trusted-host configuration")
		}
	}
	// CLI entries replace the environment list, even when explicitly empty.
	// Configured entries are additive.
	var arguments []string
	for _, option := range command.options {
		if option.name == "allow-insecure-host" {
			arguments = append(arguments, option.value)
		}
	}
	if arguments == nil {
		arguments = []string{os.Getenv("UV_INSECURE_HOST")}
	}
	for _, argument := range arguments {
		for _, value := range strings.Split(argument, " ") {
			if value != "" {
				values = append(values, value)
			}
		}
	}
	var hosts []trustedHost
	for _, value := range values {
		host, err := parseTrustedHost(value)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return func(target *url.URL) bool {
		if target == nil {
			return false
		}
		name := strings.ToLower(target.Hostname())
		scheme := strings.ToLower(target.Scheme)
		if strings.Contains(name, ":") {
			name = "[" + name + "]"
		}
		port := target.Port()
		// Rust's URL type removes default ports before TrustedHost::matches.
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
		for _, host := range hosts {
			if host.wildcard || (host.host == name && (host.scheme == "" || host.scheme == scheme) && (host.port == "" || host.port == port)) {
				return true
			}
		}
		return false
	}, nil
}

func parseTrustedHost(value any) (trustedHost, error) {
	invalid := errors.New("invalid uv trusted-host configuration")
	var host trustedHost
	switch value := value.(type) {
	case string:
		if value == "*" {
			return trustedHost{wildcard: true}, nil
		}
		for _, scheme := range []string{"https", "http"} {
			if strings.HasPrefix(value, scheme+"://") {
				host.scheme, value = scheme, strings.TrimPrefix(value, scheme+"://")
				break
			}
		}
		name, port, supplied := strings.Cut(value, ":")
		host.host, _, _ = strings.Cut(name, "/")
		if supplied {
			parsed, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return trustedHost{}, invalid
			}
			host.port = strconv.FormatUint(parsed, 10)
		}
	case map[string]any:
		var ok bool
		if host.host, ok = value["host"].(string); !ok {
			return trustedHost{}, invalid
		}
		if scheme, exists := value["scheme"]; exists {
			if host.scheme, ok = scheme.(string); !ok {
				return trustedHost{}, invalid
			}
		}
		if raw, exists := value["port"]; exists {
			port, ok := raw.(int64)
			if !ok || port < 0 || port > 65535 {
				return trustedHost{}, invalid
			}
			host.port = strconv.FormatInt(port, 10)
		}
	default:
		return trustedHost{}, invalid
	}
	return host, nil
}
