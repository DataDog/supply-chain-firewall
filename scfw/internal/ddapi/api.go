// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

const (
	// The environment variable under which SCFW looks for a Datadog site parameter.
	ddSiteVar = "DD_SITE"

	// Default Datadog site value used when `DD_SITE` is not set.
	ddSiteDefault = "datadoghq.com"
)

// Returns the currently configured Datadog site parameter or `ddSiteDefault`.
func resolveDdSite() string {
	if site := os.Getenv(ddSiteVar); site != "" {
		return site
	}
	return ddSiteDefault
}

// postDatadogAPI POSTs body to the given Code Security API endpoint (relative to the
// resolved Datadog site) and returns the raw response body. It attaches the resolved
// Datadog credentials, logs the request/response bodies at DEBUG, and treats any
// non-2xx status as an error.
func postDatadogAPI(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	ddAPIKey, ddAppKey, _, _, err := DDCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Datadog credentials: %w", err)
	}

	slog.Debug("Code Security API request", "endpoint", endpoint, "body", string(body))

	url := fmt.Sprintf("https://api.%s/%s", resolveDdSite(), endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build Code Security API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("dd-api-key", ddAPIKey)
	req.Header.Set("dd-application-key", ddAppKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send Code Security API request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Code Security API response: %w", err)
	}

	slog.Debug("Code Security API response", "endpoint", endpoint, "body", string(respBody))

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("received unexpected status from Code Security API: %s", resp.Status)
	}

	return respBody, nil
}

// Generate a random UUIDv4 string to identify an API request.
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
