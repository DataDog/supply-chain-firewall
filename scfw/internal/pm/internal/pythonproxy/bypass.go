// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pythonproxy

import (
	"errors"
	"net"
	"strings"
)

// ValidateHTTPSBypass rejects Requests rules that distinguish an explicit :443
// from its implicit default. CONNECT and the inner Host header do not retain that
// distinction, so interception cannot choose the native route without guessing.
// Call only when bypassing actually changes the effective HTTPS proxy.
func ValidateHTTPSBypass(noProxy, urllibNoProxy string, loose bool) error {
	patterns := strings.Split(strings.ReplaceAll(noProxy, " ", ""), ",")
	for _, pattern := range patterns {
		host, matches := strings.CutSuffix(pattern, ":443")
		if !matches || (host == "" && !loose) || host != strings.ToLower(host) || strings.ContainsAny(host, "*[]") {
			continue
		}
		// Requests prepares IDN URL hosts as ASCII before matching NO_PROXY.
		if strings.IndexFunc(host, func(r rune) bool { return r > 127 }) >= 0 {
			continue
		}
		// Requests never applies host:port rules to IPv4 literals. Its domain branch
		// also handles bare IPv6; bracketed IPv6 patterns do not match that branch.
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() != nil {
			continue
		}
		if strings.Contains(host, ":") && ip == nil &&
			(!loose || (net.ParseIP("::"+host) == nil && net.ParseIP("::"+strings.TrimPrefix(host, ":")) == nil)) {
			continue
		}
		if coveredHTTPSBypass(host, patterns, urllibNoProxy, loose) {
			continue
		}
		return errors.New("cannot preserve NO_PROXY with explicit HTTPS port 443 through interception; use a hostname-only bypass or a nondefault port")
	}
	return nil
}

// A hostname-only rule that covers the port rule removes the distinction between
// explicit and implicit ports. Requests and urllib can select different lists.
func coveredHTTPSBypass(host string, patterns []string, urllibNoProxy string, loose bool) bool {
	host = strings.TrimLeft(host, ".")
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		suffix := strings.TrimLeft(pattern, ".")
		if (!loose && (host == suffix || strings.HasSuffix(host, "."+suffix))) ||
			(loose && strings.HasSuffix(host, pattern)) {
			return true
		}
	}
	if urllibNoProxy == "*" {
		return true
	}
	hostOnly := host
	if index := strings.LastIndexByte(host, ':'); index >= 0 && strings.Trim(host[index+1:], "0123456789") == "" {
		hostOnly = host[:index]
	}
	for _, pattern := range strings.Split(urllibNoProxy, ",") {
		suffix := strings.ToLower(strings.TrimLeft(strings.TrimSpace(pattern), "."))
		if suffix != "" && (host == suffix || hostOnly == suffix || strings.HasSuffix(host, "."+suffix) || strings.HasSuffix(hostOnly, "."+suffix)) {
			return true
		}
	}
	return false
}
