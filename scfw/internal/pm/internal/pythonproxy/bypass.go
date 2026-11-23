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
func ValidateHTTPSBypass(noProxy string, loose bool) error {
	for _, pattern := range strings.Split(strings.ReplaceAll(noProxy, " ", ""), ",") {
		host, matches := strings.CutSuffix(pattern, ":443")
		if !matches || (host == "" && !loose) || host != strings.ToLower(host) || strings.ContainsAny(host, "*[]") {
			continue
		}
		// Requests never applies host:port rules to IPv4 literals. Its domain branch
		// also handles bare IPv6; bracketed IPv6 patterns do not match that branch.
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			continue
		}
		return errors.New("cannot preserve NO_PROXY with explicit HTTPS port 443 through interception; use a hostname-only bypass or a nondefault port")
	}
	return nil
}
