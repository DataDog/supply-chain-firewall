// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"

// PyPIClassifierOptions supplies configured source roots without modifying the project.
func (poetry Poetry) PyPIClassifierOptions(command []string) (pypi.RequestClassifierOptions, error) {
	var options pypi.RequestClassifierOptions
	settings, err := readPoetrySettings(command)
	if err != nil {
		return options, err
	}
	for _, source := range settings.sources {
		if source.URL != "" {
			options.SimpleIndexURLs = append(options.SimpleIndexURLs, source.URL)
		}
	}
	return options, nil
}
