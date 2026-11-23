// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func (s *poetryProxySettings) httpsBypassHook(_ context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if strings.HasPrefix(request.ClientIdentity, "client:") || s.git.isRequest(request) {
		return nil, nil
	}
	err := pythonproxy.ValidateHTTPSRoute(&request.URL, func(target *url.URL) (*url.URL, error) {
		candidate := request
		candidate.URL = *target
		return s.requestsProxy(candidate)
	})
	if err != nil {
		s.bypassWarning.Do(func() { slog.Error(err.Error()) })
	}
	return nil, err
}
