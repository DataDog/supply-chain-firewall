// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"net/netip"
	"net/url"
	"strings"
)

// Native Git uses libcurl's host/domain/IP matching, not Requests' host:port
// matching. See https://curl.se/libcurl/c/CURLOPT_NOPROXY.html.
func bypassesProxy(target *url.URL, noProxy string) bool {
	if noProxy == "*" {
		return true
	}
	host := strings.ToLower(target.Hostname())
	ip, ipErr := netip.ParseAddr(host)
	for _, pattern := range strings.FieldsFunc(noProxy, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if ipErr == nil {
			if address, err := netip.ParseAddr(pattern); err == nil && address == ip {
				return true
			}
			if network, err := netip.ParsePrefix(pattern); err == nil && ip.Is4() && network.Bits() > 0 && network.Contains(ip) {
				return true
			}
			continue
		}
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(pattern, "."), "."))
		name := strings.TrimSuffix(host, ".")
		if domain != "" && (name == domain || strings.HasSuffix(name, "."+domain)) {
			return true
		}
	}
	return false
}
