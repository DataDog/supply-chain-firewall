// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package build

import (
	"runtime/debug"
	"strings"
)

// Version is set at build time via:
//
//	-ldflags "-X github.com/DataDog/supply-chain-firewall/scfw/internal/build.Version={{.Version}}"
//
// It is left as "dev" for local and `go install` builds that don't set it explicitly.
var Version = "dev"

// GetVersion returns the version string to display to users. If Version wasn't
// set at build time, it falls back to the module version recorded by the Go
// toolchain, which is populated for `go install <module>@<version>` builds.
func GetVersion() string {
	if Version != "dev" {
		return Version
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
	}

	return Version
}
