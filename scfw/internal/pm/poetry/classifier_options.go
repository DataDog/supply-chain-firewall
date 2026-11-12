// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"os"
	"path/filepath"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/pelletier/go-toml/v2"
)

// PyPIClassifierOptions supplies source roots for nonstandard Simple API paths.
// Priorities and credentials stay under Poetry's control. This read-only hint
// does not replace Poetry's parser or prevent its own diagnostics for invalid
// projects; recognizable downloads are always inspected.
func (poetry Poetry) PyPIClassifierOptions(command []string) (pypi.RequestClassifierOptions, error) {
	var options pypi.RequestClassifierOptions
	directory, err := poetryProjectDirectory(command)
	if err != nil {
		return options, err
	}
	for {
		data, err := os.ReadFile(directory + string(filepath.Separator) + "pyproject.toml")
		if err == nil {
			var project struct {
				Tool struct {
					Poetry struct {
						Source []struct{ URL string } `toml:"source"`
					} `toml:"poetry"`
				} `toml:"tool"`
			}
			if toml.Unmarshal(data, &project) == nil {
				for _, source := range project.Tool.Poetry.Source {
					if source.URL != "" {
						options.SimpleIndexURLs = append(options.SimpleIndexURLs, source.URL)
					}
				}
			}
			return options, nil
		}
		parent := poetryParentDirectory(directory)
		if !os.IsNotExist(err) || parent == directory {
			return options, nil
		}
		directory = parent
	}
}
