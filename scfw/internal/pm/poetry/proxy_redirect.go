// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

const poetryRedirectDiagnostic = "Poetry/Requests cannot preserve its original proxy/TLS context across this redirect with process-only overrides; use consistent NO_PROXY/no_proxy and TLS settings for the redirect chain"

func (s *poetryProxySettings) redirectHook(_ context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if strings.HasPrefix(request.ClientIdentity, "client:") {
		return nil, nil
	}
	return func(_ context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
		switch response.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return nil, nil
		}
		location := response.Header.Get("Location")
		if location == "" {
			return nil, nil
		}
		reference, err := url.Parse(location)
		if err != nil {
			return nil, errors.New("invalid Poetry redirect")
		}
		target := request.URL.ResolveReference(reference)
		if target.Scheme != "http" && target.Scheme != "https" {
			return nil, nil
		}
		origin, err := s.route(request)
		if err != nil {
			return nil, err
		}
		next := request
		next.URL = *target
		if target.Scheme == "http" {
			next.ClientIdentity = "poetry-default"
		}
		destination, err := s.route(next)
		if err != nil {
			return nil, s.redirectCompatibilityError()
		}
		// Existing Requests proxy mappings survive rebuild_proxies even for a
		// bypassed target. Reject an unrepresentable mapping before exposing the
		// redirect instead of bypassing a required gateway.
		if origin.ProxyURL != nil && destination.ProxyURL == nil {
			candidate := request.URL
			candidate.Scheme = target.Scheme
			mapped, err := poetryProxyForURL(s.upstream)(&candidate)
			if err != nil {
				return nil, err
			}
			if request.URL.Scheme == target.Scheme || mapped != nil {
				return nil, s.redirectCompatibilityError()
			}
		}
		// Plain HTTP cannot carry a TLS client identity. Do not silently switch
		// the TLS policy of an HTTPS upstream proxy on an HTTP redirect.
		if target.Scheme == "http" && destination.ProxyURL != nil && destination.ProxyURL.Scheme == "https" && !samePoetryTLS(origin.TLS, destination.TLS) {
			return nil, s.redirectCompatibilityError()
		}
		return nil, nil
	}, nil
}

func (s *poetryProxySettings) redirectCompatibilityError() error {
	s.redirectWarning.Do(func() { slog.Error(poetryRedirectDiagnostic) })
	return errors.New(poetryRedirectDiagnostic)
}
