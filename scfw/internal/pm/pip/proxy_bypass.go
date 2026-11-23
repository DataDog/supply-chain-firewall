// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func pipHTTPSBypassHook(settings pipDiscoveryResult) proxy.RequestHook {
	var diagnostic sync.Once
	route := pipProxyForURL(settings)
	return func(_ context.Context, request proxy.Request) (proxy.ResponseHook, error) {
		if strings.HasPrefix(request.ClientIdentity, "client:") || pipNativeGitRequest(request) {
			return nil, nil
		}
		err := pythonproxy.ValidateHTTPSRoute(&request.URL, route)
		if err != nil {
			diagnostic.Do(func() { slog.Error(err.Error()) })
		}
		return nil, err
	}
}

// Git subprocesses share pip's listener but use libcurl's bypass semantics.
// Recognizable pip/Requests traffic must retain the guard even on Git-shaped URLs.
func pipNativeGitRequest(request proxy.Request) bool {
	agent := request.Header.Get("User-Agent")
	if strings.HasPrefix(agent, "pip/") || strings.HasPrefix(agent, "python-requests/") {
		return false
	}
	return strings.HasPrefix(agent, "git/") || request.URL.Query().Get("service") == "git-upload-pack" || strings.HasSuffix(request.URL.Path, "/git-upload-pack")
}
