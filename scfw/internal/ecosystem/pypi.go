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

// pyPIRegistryDomains are the URL domains associated with the PyPI registry, ported from
// ecosystem.py's ECOSYSTEM.registry_domains in the Python reference.
var pyPIRegistryDomains = []string{"pypi.org", "files.pythonhosted.org"}

// isPyPIRegistrySource reports whether source is a known PyPI registry URL, ported from
// package.py's Package.has_registry_source in the Python reference.
func isPyPIRegistrySource(source string) bool {
	u, err := url.Parse(source)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return slices.Contains(pyPIRegistryDomains, u.Hostname())
}

// resolvePyPIPublishDate returns the publication date of the given package version on
// PyPI, taken to be the latest of the release's upload timestamps.
//
// A non-empty source that isn't a known PyPI registry URL has no publish date to resolve;
// this is a no-op rather than an error, leaving it to the caller to decide how to handle
// an unresolved publish date, and the zero value of time.Time is returned in that case.
// An empty source is assumed to be the PyPI registry.
func resolvePyPIPublishDate(ctx context.Context, name, version, source string) (time.Time, error) {
	if source != "" && !isPyPIRegistrySource(source) {
		return time.Time{}, nil
	}

	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to build PyPI request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query PyPI registry: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		return time.Time{}, fmt.Errorf("received unexpected status from PyPI registry: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read PyPI response: %w", err)
	}

	return parsePyPIReleaseMetadata(body, name, version)
}

// parsePyPIReleaseMetadata decodes the JSON returned by PyPI's package metadata endpoint
// and returns the latest upload timestamp recorded for the given package version.
func parsePyPIReleaseMetadata(body []byte, name, version string) (time.Time, error) {
	var metadata struct {
		Releases map[string][]struct {
			UploadTimeISO8601 string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse PyPI response as JSON: %w", err)
	}

	releases, ok := metadata.Releases[version]
	if !ok || len(releases) == 0 {
		return time.Time{}, fmt.Errorf("package metadata missing required fields")
	}

	var latest time.Time
	for _, release := range releases {
		if release.UploadTimeISO8601 == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, release.UploadTimeISO8601)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse publication datetime %q: %w", release.UploadTimeISO8601, err)
		}
		if t.After(latest) {
			latest = t
		}
	}

	if latest.IsZero() {
		return time.Time{}, fmt.Errorf("no publication timestamp for version %s of package %s", version, name)
	}

	return latest, nil
}
