// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"errors"
	"net/url"
	"strings"
)

// EnvironmentOverrides routes standard proxy variables through this invocation.
// Adapters add their client-specific CA and configuration overrides.
func (config ClientConfig) EnvironmentOverrides() map[string]string {
	return map[string]string{
		"http_proxy": config.URL, "HTTP_PROXY": config.URL,
		"https_proxy": config.URL, "HTTPS_PROXY": config.URL,
		"all_proxy": config.URL, "ALL_PROXY": config.URL,
		"no_proxy": "", "NO_PROXY": "",
	}
}

// ParseUpstreamProxyURL normalizes HTTP(S) proxy addresses without exposing
// credentials in parsing errors. An empty address selects a direct connection.
func ParseUpstreamProxyURL(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("unsupported or invalid upstream proxy URL")
	}
	return parsed, nil
}
