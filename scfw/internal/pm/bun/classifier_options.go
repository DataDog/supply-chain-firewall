// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"net/url"
	"slices"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
)

// NpmClassifierOptions supplies the configured and scoped registry URLs.
func (b Bun) NpmClassifierOptions(command []string) (npmregistry.ClassifierOptions, error) {
	settings, _, err := b.settings(command)
	if err != nil {
		return npmregistry.ClassifierOptions{}, err
	}
	var urls []string
	for _, value := range settings.Registries {
		parsed, err := url.Parse(value)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && !slices.Contains(urls, value) {
			urls = append(urls, value)
		}
	}
	return npmregistry.ClassifierOptions{RegistryURLs: urls}, nil
}
