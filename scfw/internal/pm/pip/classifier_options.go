// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"net/url"
)

// PyPIClassifierOptions supplies explicit argument/configuration source URLs.
func (pip Pip) PyPIClassifierOptions(command []string) (pypi.RequestClassifierOptions, error) {
	settings, err := pip.settings(command)
	if err != nil {
		return pypi.RequestClassifierOptions{}, err
	}
	httpOnly := func(values []string) []string {
		var urls []string
		for _, value := range values {
			parsed, err := url.Parse(value)
			if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				urls = append(urls, value)
			}
		}
		return urls
	}
	return pypi.RequestClassifierOptions{SimpleIndexURLs: httpOnly(settings.Indexes), DirectArtifactURLs: httpOnly(settings.Direct), SelectArchive: pip.selectArchive, RetainArchiveContentEncoding: true}, nil
}
