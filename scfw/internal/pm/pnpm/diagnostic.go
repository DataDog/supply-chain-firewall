// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"context"
	"os"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// DiagnosticInfo distinguishes installed and project-selected versions without
// executing another manager or changing the adapter's switching rules.
func (p Pnpm) DiagnosticInfo(_ context.Context, command []string) pm.DiagnosticInfo {
	if p.versionErr != nil {
		return pm.DiagnosticInfo{Version: "unknown"}
	}
	info := pm.DiagnosticInfo{Version: p.installed.String(), InstalledVersion: p.installed.String()}
	cwd, err := os.Getwd()
	if err != nil {
		info.Version = "unknown"
		return info
	}
	version := p.effectiveVersion(cwd, p.installed.Major, command)
	if version.Major != p.installed.Major {
		version = p.effectiveVersion(cwd, version.Major, command)
	}
	info.Version = version.String()
	return info
}
