// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pythonproxy

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

var ErrAmbiguousHTTPSBypass = errors.New("cannot preserve NO_PROXY with explicit HTTPS port 443 through interception; use a hostname-only bypass or a nondefault port")

// ValidateHTTPSRoute checks only the intercepted destination. CONNECT and the
// inner Host header cannot retain whether its default port was written explicitly.
// The adapter supplies its complete native proxy selection, including fallbacks.
func ValidateHTTPSRoute(target *url.URL, route func(*url.URL) (*url.URL, error)) error {
	if target.Scheme != "https" || (target.Port() != "" && target.Port() != "443") {
		return nil
	}
	implicit, explicit := *target, *target
	implicit.Host = target.Hostname()
	if strings.Contains(implicit.Host, ":") {
		implicit.Host = "[" + implicit.Host + "]"
	}
	explicit.Host = net.JoinHostPort(target.Hostname(), "443")
	first, err := route(&implicit)
	if err != nil {
		return errors.New("could not resolve Python proxy route")
	}
	second, err := route(&explicit)
	if err != nil {
		return errors.New("could not resolve Python proxy route")
	}
	if !sameProxyEndpoint(first, second) {
		return ErrAmbiguousHTTPSBypass
	}
	return nil
}

func sameProxyEndpoint(a, b *url.URL) bool {
	if a == nil || b == nil {
		return a == b
	}
	port := func(u *url.URL) string {
		if value := u.Port(); value != "" {
			return value
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b) && a.User.String() == b.User.String()
}
