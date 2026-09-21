// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package pip owns pip index discovery and process-local overrides.
package pip

import (
	"context"
	"errors"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	pypiecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
)

type Manager struct{}

func (Manager) Name() string { return "pip" }

func (Manager) Registries(ctx context.Context, executable string, _ []string) (proxy.RegistryConfiguration, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "list")
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	values := parseConfigList(string(output))
	keyringProvider := os.Getenv("PIP_KEYRING_PROVIDER")
	if keyringProvider == "" {
		keyringProvider = lastValue(values, "keyring-provider")
	}
	if keyringProvider != "" && !strings.EqualFold(keyringProvider, "disabled") {
		return proxy.RegistryConfiguration{}, errors.New("pip proxy mode does not support keyring authentication; use URL or netrc credentials")
	}
	trustedHost := os.Getenv("PIP_TRUSTED_HOST")
	if trustedHost == "" {
		trustedHost = lastValue(values, "trusted-host")
	}
	if trustedHost != "" {
		return proxy.RegistryConfiguration{}, errors.New("pip proxy mode does not support trusted-host TLS exceptions; configure a CA bundle with PIP_CERT")
	}
	caFile := os.Getenv("PIP_CERT")
	if caFile == "" {
		caFile = lastValue(values, "cert")
	}
	index := os.Getenv("PIP_INDEX_URL")
	if index == "" {
		index = lastValue(values, "index-url")
	}
	if index == "" {
		index = shared.DefaultPyPIRegistry
	}
	registry, err := shared.ParseURL("pip index-url", index)
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	extra := os.Getenv("PIP_EXTRA_INDEX_URL")
	if extra == "" {
		extra = lastValue(values, "extra-index-url")
	}
	named := make(map[string]*url.URL)
	for index, value := range strings.Fields(extra) {
		parsed, parseErr := shared.ParseURL("pip extra-index-url", value)
		if parseErr != nil {
			return proxy.RegistryConfiguration{}, parseErr
		}
		named["extra-"+strconv.Itoa(index)] = parsed
	}
	return proxy.RegistryConfiguration{Default: registry, Named: named, Handler: pypiecosystem.Handler{}, UseNetrc: true, CAFile: caFile}, nil
}

func parseConfigList(output string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		values[strings.TrimSpace(key)] = value
	}
	return values
}

func lastValue(values map[string]string, suffix string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		normalized := strings.ToLower(key)
		if normalized == suffix || strings.HasSuffix(normalized, "."+suffix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return values[keys[len(keys)-1]]
}

func (Manager) Prepare(_ string, args []string, registryURL string, named map[string]string) (proxy.PreparedCommand, error) {
	extra := shared.SortedNamedOptions(named, func(_, value string) string { return value })
	return proxy.PreparedCommand{
		Args: args,
		Env: shared.OverrideEnvironment(map[string]string{
			"PIP_INDEX_URL":       registryURL,
			"PIP_EXTRA_INDEX_URL": strings.Join(extra, " "),
		}),
	}, nil
}
