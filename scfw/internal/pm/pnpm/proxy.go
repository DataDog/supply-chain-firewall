// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"errors"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

func (p Pnpm) UpstreamProxy(command []string) (httpproxy.Config, error) {
	settings, err := p.settings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	config := httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy}
	if settings.NoProxyAll {
		config.NoProxy = "*"
	}
	return config, validateUpstream(settings)
}

// validateUpstream rejects the proxies pnpm selects when the core cannot use
// them, without echoing a URL that may carry credentials. pnpm would connect
// directly for an unsupported scheme; SCFW fails instead.
func validateUpstream(settings pnpmSettings) error {
	for _, value := range []string{settings.HTTPS, settings.HTTP} {
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || !strings.Contains(value, "://") || parsed.Hostname() == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("unsupported or invalid pnpm upstream proxy URL")
		}
	}
	return nil
}
