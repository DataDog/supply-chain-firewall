// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// npmRegistryDomains are the URL domains associated with the npm registry, ported from
// ecosystem.py's ECOSYSTEM.registry_domains in the Python reference.
var npmRegistryDomains = []string{"registry.npmjs.org"}

// isNpmRegistrySource reports whether source is a known npm registry URL, ported from
// package.py's Package.has_registry_source in the Python reference.
func isNpmRegistrySource(source string) bool {
	u, err := url.Parse(source)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return slices.Contains(npmRegistryDomains, u.Hostname())
}

// resolveNpmPublishDate returns the publication date of the given package version on npm.
//
// A non-empty source that isn't a known npm registry URL has no publish date to resolve;
// this is a no-op rather than an error, leaving it to the caller to decide how to handle
// an unresolved publish date, and the zero value of time.Time is returned in that case.
// An empty source is assumed to be the npm registry.
func resolveNpmPublishDate(ctx context.Context, name, version, source string) (time.Time, error) {
	if source != "" && !isNpmRegistrySource(source) {
		return time.Time{}, nil
	}

	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to build npm request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query npm registry: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		return time.Time{}, fmt.Errorf("received unexpected status from npm registry: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read npm response: %w", err)
	}

	return parseNpmPackageMetadata(body, name, version)
}

// parseNpmPackageMetadata decodes the JSON returned by the npm registry's package metadata
// endpoint and returns the publish timestamp recorded for the given package version.
func parseNpmPackageMetadata(body []byte, name, version string) (time.Time, error) {
	var metadata struct {
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse npm response as JSON: %w", err)
	}

	releaseTimestamp, ok := metadata.Time[version]
	if !ok || releaseTimestamp == "" {
		return time.Time{}, fmt.Errorf("metadata for npm package %s missing required fields", name)
	}

	t, err := time.Parse(time.RFC3339Nano, releaseTimestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse publication datetime %q: %w", releaseTimestamp, err)
	}

	return t, nil
}
