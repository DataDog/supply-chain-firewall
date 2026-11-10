// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"net/url"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
)

type systemProxySettings struct {
	proxies       map[string]string
	exceptions    []string
	excludeSimple bool
}

// urllib falls back to native settings only when the environment proxy map is empty.
func pipProxies(readSystem func() (systemProxySettings, error)) (systemProxySettings, error) {
	if proxies := pipEnvironmentProxies(); len(proxies) != 0 {
		return systemProxySettings{proxies: proxies}, nil
	}
	return readSystem()
}
func readSystemProxies() (systemProxySettings, error) {
	value, err := pythonproxy.ReadSystem()
	return fromNativeProxy(value), err
}
func fromNativeProxy(value pythonproxy.Settings) systemProxySettings {
	return systemProxySettings{proxies: value.Proxies, exceptions: value.Exceptions, excludeSimple: value.ExcludeSimple}
}
func (s systemProxySettings) bypasses(target *url.URL) bool {
	return (pythonproxy.Settings{Proxies: s.proxies, Exceptions: s.exceptions, ExcludeSimple: s.excludeSimple}).Bypasses(target)
}
