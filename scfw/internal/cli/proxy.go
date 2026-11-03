// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"fmt"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"syscall"
)

// proxyEnabledVar is the feature flag that routes `scfw run` through the
// package manager proxy. Only the exact value "1" enables it.
const proxyEnabledVar = "SCFW_PROXY_ENABLED"

func proxyEnabled() bool {
	return os.Getenv(proxyEnabledVar) == "1"
}

// runThroughProxy runs command through a proxy created for this invocation
// alone, chained to the package manager's pre-existing upstream proxy. The proxy
// is stopped once the command exits, whatever the outcome.
// commandErr is the command's own failure; setupErr means the command never ran.
func runThroughProxy(
	ctx context.Context,
	runner pm.ProxyRunner,
	command []string,
	controller ecosystemProxyController,
) (commandErr, setupErr error) {
	// SIGINT already cancels ctx (see main). Also treat SIGTERM as cancellation
	// here, rather than letting it end the process before the proxy is cleaned up.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer stop()

	upstream, err := runner.UpstreamProxy(command)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream proxy: %w", err)
	}
	options := proxy.Options{Upstream: upstream}
	if controller != nil {
		options = controller(ctx, upstream)
		options.Upstream = upstream
	}

	server, err := proxy.Start(ctx, options)
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

// ecosystemProxyController is the narrow CLI integration boundary between a concrete
// package-manager ProxyRunner and ecosystem-specific proxy behavior. Generic
// ProxyRunners pass nil; future Python adapter wiring can opt into PyPI without
// moving registry parsing or policy orchestration into the adapter.
type ecosystemProxyController func(context.Context, httpproxy.Config) proxy.Options

func newPublicationHTTPClient(upstream httpproxy.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxyFunc := upstream.ProxyFunc()
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		return proxyFunc(request.URL)
	}
	return &http.Client{Transport: transport}
}

// redactCommandArguments returns a reporting/logging copy of a command with
// credentials removed from absolute HTTP(S) URL arguments. The package manager
// still receives the original arguments.
func redactCommandArguments(command []string) []string {
	redacted := make([]string, len(command))
	for index, argument := range command {
		redacted[index] = commandURLPattern.ReplaceAllStringFunc(argument, redactCommandURL)
	}
	return redacted
}

var commandURLPattern = regexp.MustCompile(`(?i)https?://[^\s]+`)

func redactCommandURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		// If the URL cannot be safely decomposed, none of it is safe to log.
		return "[REDACTED_URL]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}
