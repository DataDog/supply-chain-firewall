// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// proxyEnabledVar is the feature flag that routes `scfw run` through the
// package manager proxy. Only the exact value "1" enables it.
const proxyEnabledVar = "SCFW_PROXY_ENABLED"

func proxyEnabled() bool {
	return os.Getenv(proxyEnabledVar) == "1"
}

// runThroughProxy runs command through a proxy created for this invocation
// alone. The proxy is stopped once the command exits, whatever the outcome.
// commandErr is the command's own failure; setupErr means the command never ran.
func runThroughProxy(ctx context.Context, runner pm.ProxyRunner, command []string) (commandErr, setupErr error) {
	// SIGINT already cancels ctx (see main). Also treat SIGTERM as cancellation
	// here, rather than letting it end the process before the proxy is cleaned up.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer stop()

	server, err := proxy.Start(proxy.Options{})
	if err != nil {
		return nil, err
	}
	// Deferred so the proxy is also stopped if the command panics.
	defer func() {
		if err := server.Close(); err != nil {
			slog.Warn("failed to stop package manager proxy cleanly", "error", err)
		}
	}()

	slog.Debug("running package manager command through proxy")
	return runner.RunCommandThroughProxy(ctx, command, server.ClientConfig()), nil
}
