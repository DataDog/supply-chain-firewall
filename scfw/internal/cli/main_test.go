// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"os"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/githook"
)

// The test binary stands in for the scfw executable that git hook scripts run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "git-hook" {
		os.Exit(githook.Run(context.Background(), os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
