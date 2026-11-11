// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"net/url"
	"slices"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
)

// NpmClassifierOptions supplies the configured and scoped registry URLs.
func (yarn Yarn) NpmClassifierOptions(command []string) (npmregistry.ClassifierOptions, error) {
	gen, err := yarn.generation()
	if err != nil {
		return npmregistry.ClassifierOptions{}, err
	}
	registries := []string{"https://registry.yarnpkg.com"}
	if gen == classic {
		settings, err := yarn.classicSettings(command)
		if err != nil {
			return npmregistry.ClassifierOptions{}, err
		}
		registries = settings.Registries
	}
	// Only absolute HTTP(S) URLs identify registries; anything else would make
	// the classifier reject the whole run for a setting Yarn itself cannot use.
	var urls []string
	for _, value := range registries {
		parsed, err := url.Parse(value)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && !slices.Contains(urls, value) {
			urls = append(urls, value)
		}
	}
	return npmregistry.ClassifierOptions{RegistryURLs: urls}, nil
}
