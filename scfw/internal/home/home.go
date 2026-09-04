// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package home resolves Supply Chain Firewall's home directory, where it caches
// verification data and writes its local log.
package home

import (
	"log/slog"
	"os"
	"path/filepath"
)

// The environment variable under which SCFW looks for its home directory.
const scfwHomeVar = "SCFW_HOME"

// The home directory's name within the user's cache directory.
const defaultDirName = "scfw"

// Dir returns SCFW's home directory: SCFW_HOME when set, otherwise a directory
// under the user's cache directory. It returns "" only when neither is
// available, in which case callers proceed without caching or local logging.
func Dir() string {
	if home := os.Getenv(scfwHomeVar); home != "" {
		return home
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		slog.Debug("Could not determine a home directory for SCFW", "error", err)
		return ""
	}
	return filepath.Join(cache, defaultDirName)
}
