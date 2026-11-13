// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"maps"
	"net/url"
	"slices"
	"strings"
)

// Bypasses mirrors @npmcli/agent and pnpm: an entry matches when its non-empty
// dot segments equal the host's, compared from the right. There is no
// wildcard, matching is case-sensitive, and an entry with a port never matches.
func Bypasses(target *url.URL, noProxy string) bool {
	host := strings.Split(target.Hostname(), ".")
	slices.Reverse(host)
	for entry := range strings.SplitSeq(noProxy, ",") {
		var segments []string
		for segment := range strings.SplitSeq(strings.TrimSpace(entry), ".") {
			if segment != "" {
				segments = append(segments, segment)
			}
		}
		if len(segments) == 0 || len(segments) > len(host) {
			continue
		}
		slices.Reverse(segments)
		if slices.Equal(host[:len(segments)], segments) {
			return true
		}
	}
	return false
}

// OverrideVariants gives every variant of a canonical key already present in
// environ the canonical value. Node package managers read their variables
// case-insensitively and accept dashes for underscores, while the core
// replaces exact keys only.
func OverrideVariants(environ []string, canonical map[string]string) map[string]string {
	normalized := make(map[string]string, len(canonical))
	for key, value := range canonical {
		normalized[strings.ToLower(key)] = value
	}
	overrides := maps.Clone(canonical)
	for _, item := range environ {
		key, _, _ := strings.Cut(item, "=")
		if value, found := normalized[strings.ReplaceAll(strings.ToLower(key), "-", "_")]; found {
			overrides[key] = value
		}
	}
	return overrides
}
