// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// DiagnosticInfo exposes already-discovered version state only during capture.
func (npm Npm) DiagnosticInfo(context.Context, []string) pm.DiagnosticInfo {
	if npm.versionErr != nil {
		return pm.DiagnosticInfo{Version: "unknown"}
	}
	return pm.DiagnosticInfo{Version: npm.version.String()}
}
