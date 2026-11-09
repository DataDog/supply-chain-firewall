// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pythonproxy

import (
	"os"
	"strings"
)

// Environment returns urllib's proxy map, including lowercase precedence,
// explicit removals, and CGI handling. It does not apply adapter-specific fallbacks.
func Environment() map[string]string {
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
