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
		if strings.HasPrefix(request.ClientIdentity, "client:") {
			return nil, nil
		}
		err := pythonproxy.ValidateHTTPSRoute(&request.URL, route)
		if err != nil {
			diagnostic.Do(func() { slog.Error(err.Error()) })
		}
		return nil, err
	}
}
