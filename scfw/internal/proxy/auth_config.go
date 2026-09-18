// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bytes"
	"fmt"
	"os"
)

const inheritedNPMConfigPath = "/dev/fd/3"

// npmAuthConfig exposes npm's original user configuration plus the ephemeral
// loopback credential through a platform-protected descriptor inherited by npm
// as descriptor 3. It is never present in argv, the environment, or the
// filesystem namespace, and configuration writes to it fail.
type npmAuthConfig struct {
	file    *os.File
	path    string
	cleanup func() error
}

func newNPMAuthConfig(originalPath, localAuthLine string) (*npmAuthConfig, error) {
	var original []byte
	if originalPath != "" {
		contents, err := os.ReadFile(originalPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read npm user configuration: %w", err)
		}
		original = contents
	}
	contents := bytes.Clone(original)
	if len(contents) > 0 && contents[len(contents)-1] != '\n' {
		contents = append(contents, '\n')
	}
	contents = append(contents, localAuthLine...)
	file, cleanup, err := newProtectedNPMConfig(contents)
	if err != nil {
		return nil, err
	}
	return &npmAuthConfig{file: file, path: inheritedNPMConfigPath, cleanup: cleanup}, nil
}

func (config *npmAuthConfig) Close() error {
	return config.cleanup()
}
