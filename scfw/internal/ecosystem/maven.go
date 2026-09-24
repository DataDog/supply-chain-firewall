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
	"strings"
	"time"
)

var mavenRegistryDomains = []string{"repo.maven.apache.org", "repo1.maven.org"}

var mavenSearchEndpoint = "https://search.maven.org/solrsearch/select"

func isMavenRegistrySource(source string) bool {
	u, err := url.Parse(source)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return slices.Contains(mavenRegistryDomains, u.Hostname())
}

// resolveMavenPublishDate returns Maven Central's Last-Modified timestamp for a
// known artifact. Without a source URL it falls back to the Central search index,
// whose timestamps are milliseconds since the Unix epoch.
func resolveMavenPublishDate(ctx context.Context, name, version, source string) (time.Time, error) {
	if source != "" && !isMavenRegistrySource(source) {
		return time.Time{}, nil
	}
	if source != "" {
		return resolveMavenArtifactPublishDate(ctx, source)
	}

	groupID, artifactID, ok := strings.Cut(name, ":")
	if !ok || groupID == "" || artifactID == "" || strings.Contains(artifactID, ":") {
		return time.Time{}, fmt.Errorf("invalid Maven package name %q (expected groupId:artifactId)", name)
	}

	query := url.Values{
		"core": {"gav"},
		"q":    {fmt.Sprintf(`g:%q AND a:%q AND v:%q`, groupID, artifactID, version)},
		"rows": {"1"},
		"wt":   {"json"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mavenSearchEndpoint+"?"+query.Encode(), nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to build Maven Central request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query Maven Central: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		return time.Time{}, fmt.Errorf("received unexpected status from Maven Central: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read Maven Central response: %w", err)
	}
	return parseMavenSearchResponse(body, name, version)
}

func resolveMavenArtifactPublishDate(ctx context.Context, source string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, source, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to build Maven Central artifact request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query Maven Central artifact: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		return time.Time{}, fmt.Errorf("received unexpected status from Maven Central artifact: %s", resp.Status)
	}
	lastModified := resp.Header.Get("Last-Modified")
	if lastModified == "" {
		return time.Time{}, fmt.Errorf("artifact response from Maven Central is missing Last-Modified")
	}
	published, err := http.ParseTime(lastModified)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse Maven Central Last-Modified %q: %w", lastModified, err)
	}
	return published.UTC(), nil
}

func parseMavenSearchResponse(body []byte, name, version string) (time.Time, error) {
	var result struct {
		Response struct {
			Docs []struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse Maven Central response as JSON: %w", err)
	}
	if len(result.Response.Docs) == 0 || result.Response.Docs[0].Timestamp <= 0 {
		return time.Time{}, fmt.Errorf("metadata for Maven Central package %s@%s missing required fields", name, version)
	}
	return time.UnixMilli(result.Response.Docs[0].Timestamp).UTC(), nil
}
