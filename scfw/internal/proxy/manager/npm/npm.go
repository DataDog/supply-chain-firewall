// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package npm owns npm configuration discovery and invocation.
package npm

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// Run uses npm's hardened npmrc, lifecycle-script, credential, and lockfile
// handling while the other npm-compatible managers use the shared runner.
func Run(ctx context.Context, executable string, args []string, streams proxy.Streams, options proxy.Options) error {
	config, err := loadConfig(ctx, executable)
	if err != nil {
		return err
	}
	return proxy.RunNPMWithConfig(ctx, executable, args, streams, options, config)
}

func loadConfig(ctx context.Context, executable string) (proxy.NPMConfig, error) {
	command := exec.CommandContext(ctx, executable, "config", "list", "--json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return proxy.NPMConfig{}, fmt.Errorf("dump npm configuration: %w: %s", err, detail)
		}
		return proxy.NPMConfig{}, fmt.Errorf("dump npm configuration: %w", err)
	}
	return proxy.LoadNPMConfigData(ctx, executable, stdout.Bytes())
}
