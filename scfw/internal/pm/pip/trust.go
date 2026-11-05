// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"net/url"
	"strings"
)

// pipTrustURL matches the literal authorities pip uses for its insecure adapters.
// An omitted port permits any port; an explicit port must appear in the URL.
// Asterisks are literal characters, never wildcard trust exceptions.
func pipTrustURL(values []string) func(*url.URL) bool {
	var hosts []*url.URL
	for _, value := range values {
		if strings.Count(value, ":") >= 2 && !strings.ContainsAny(value, "@[") {
			value = "[" + value + "]"
		}
		host, err := url.Parse("https://" + value)
		if err == nil && host.Host != "" && host.Host == value {
			hosts = append(hosts, host)
		}
	}
	return func(target *url.URL) bool {
		if target == nil || (target.Scheme != "http" && target.Scheme != "https") {
			return false
		}
		for _, host := range hosts {
			if strings.EqualFold(target.Host, host.Host) ||
				(host.Port() == "" && strings.HasPrefix(strings.ToLower(target.Host), strings.ToLower(host.Host)+":")) {
				return true
			}
		}
		return false
	}
}
