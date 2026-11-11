// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"errors"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func (yarn Yarn) UpstreamProxy(command []string) (httpproxy.Config, error) {
	gen, err := yarn.generation()
	if err != nil {
		return httpproxy.Config{}, err
	}
	if gen != classic {
		return httpproxy.Config{}, nil
	}
	settings, err := yarn.classicSettings(command)
	if err != nil {
		return httpproxy.Config{}, err
	}
	config := httpproxy.Config{HTTPSProxy: settings.HTTPS, HTTPProxy: settings.HTTP, NoProxy: settings.NoProxy}
	return config, validateUpstream(config)
}

// validateUpstream rejects proxies the core cannot use, without echoing a URL
// that may carry credentials.
func validateUpstream(config httpproxy.Config) error {
	for _, value := range []string{config.HTTPSProxy, config.HTTPProxy} {
		if _, err := proxy.ParseUpstreamProxyURL(value); err != nil {
			return errors.New("unsupported or invalid yarn upstream proxy URL")
		}
	}
	return nil
}
