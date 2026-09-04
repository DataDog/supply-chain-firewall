// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package osv defines a package verifier for the OSV.dev advisory database.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/home"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

const (
	// The OSV.dev API query endpoint.
	osvQueryURL = "https://api.osv.dev/v1/query"

	// URL prefixes used in finding and failure messages.
	osvVulnerabilityURLPrefix = "https://osv.dev/vulnerability"

	// The environment variable under which the verifier looks for a file of OSV
	// advisory ID patterns to ignore.
	ignoreListVar = "SCFW_OSV_VERIFIER_IGNORE"

	// The verifier's directory, relative to SCFW's home directory, where the
	// default ignore list is looked up.
	verifierHome = "osv_verifier"

	// The default ignore-list file within the verifier's home directory.
	ignoreListName = "ignore.txt"

	// The OSV.dev API is sometimes quite slow, hence the generous timeout.
	queryTimeout = 10 * time.Second

	// Safety cap on query pagination, guarding against a misbehaving API.
	maxQueryPages = 100
)

// Verifier verifies packages against the OSV.dev advisory database. Advisories
// with MAL IDs are reported as CRITICAL findings; all others are reported as
// WARNING findings.
type Verifier struct {
	queryURL   string
	client     *http.Client
	ignoredIDs []*regexp.Regexp
}

// New returns an OsvVerifier querying the OSV.dev advisory database, honoring
// the configured ignore list if one is readable. An unreadable or missing
// ignore list only disables ignoring, never verification.
func New() Verifier {
	return newVerifier(osvQueryURL)
}

// newVerifier returns an OsvVerifier querying queryURL, for tests.
func newVerifier(queryURL string) Verifier {
	return Verifier{
		queryURL:   queryURL,
		client:     &http.Client{Timeout: queryTimeout},
		ignoredIDs: readIgnoredIDs(),
	}
}

// readIgnoredIDs returns the OSV advisory ID patterns to ignore, read from the
// file named by SCFW_OSV_VERIFIER_IGNORE or, failing that, the default ignore
// list in SCFW's home directory. Lines are regular expression patterns matched
// against advisory IDs in full; MAL advisories are never ignored.
func readIgnoredIDs() []*regexp.Regexp {
	var path string
	if custom := os.Getenv(ignoreListVar); custom != "" {
		path = custom
	} else if dir := home.Dir(); dir != "" {
		path = filepath.Join(dir, verifierHome, ignoreListName)
	} else {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv(ignoreListVar) != "" {
			slog.Warn("Failed to read OSV advisory ignore list", "path", path, "error", err)
		}
		return nil
	}

	var ignoredIDs []*regexp.Regexp
	for _, line := range strings.Fields(string(data)) {
		if strings.HasPrefix(line, "MAL") {
			slog.Warn("OSV malicious package (MAL) advisories will not be ignored", "pattern", line)
			continue
		}
		// Match advisory IDs against the pattern in full, mirroring the OSV.dev
		// ignore-list convention of fullmatch patterns.
		pattern, err := regexp.Compile("^(?:" + line + ")$")
		if err != nil {
			slog.Warn("Ignoring invalid OSV advisory ID pattern", "pattern", line, "error", err)
			continue
		}
		ignoredIDs = append(ignoredIDs, pattern)
	}
	return ignoredIDs
}

// Name returns the verifier's name.
func (Verifier) Name() string {
	return "OsvVerifier"
}

// queryRequest is the body of an OSV.dev query request.
type queryRequest struct {
	Version   string          `json:"version"`
	Package   queryRequestPkg `json:"package"`
	PageToken string          `json:"page_token,omitempty"`
}

type queryRequestPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// queryResponse is the body of an OSV.dev query response.
type queryResponse struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// Verify queries the given package against the OSV.dev advisory database.
//
// The returned error is non-nil only when the package is outside the verifier's
// purview (unsupported ecosystem or non-registry artifact source) or when the
// package could not be verified against the OSV.dev API.
func (v Verifier) Verify(ctx context.Context, pkg pm.Package) ([]evaluation.Finding, error) {
	if pkg.Ecosystem != ecosystem.NPM && pkg.Ecosystem != ecosystem.PYPI {
		return nil, fmt.Errorf("package ecosystem %s is not supported", pkg.Ecosystem)
	}
	if pkg.Source != "" && !ecosystem.HasRegistrySource(pkg.Ecosystem, pkg.Source) {
		return nil, fmt.Errorf("cannot verify package with non-%s registry source", pkg.Ecosystem)
	}

	vulns, err := v.queryAdvisories(ctx, pkg)
	if err != nil {
		slog.Warn("Failed to query the OSV.dev API", "package", pkg.Name, "error", err)
		return nil, err
	}

	var findings []evaluation.Finding
	for _, vulnID := range vulns {
		if strings.HasPrefix(vulnID, "MAL") || !slices.ContainsFunc(v.ignoredIDs, func(pattern *regexp.Regexp) bool {
			return pattern.MatchString(vulnID)
		}) {
			findings = append(findings, v.finding(pkg, vulnID))
		}
	}
	return findings, nil
}

// queryAdvisories queries the OSV.dev API for the given package, following
// pagination, and returns the IDs of all advisories for the package.
func (v Verifier) queryAdvisories(ctx context.Context, pkg pm.Package) ([]string, error) {
	query := queryRequest{
		Version: pkg.Version,
		Package: queryRequestPkg{Name: pkg.Name, Ecosystem: string(pkg.Ecosystem)},
	}

	var ids []string
	for range maxQueryPages {
		body, err := json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal OSV.dev query: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.queryURL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to build OSV.dev query request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := v.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to query the OSV.dev API: %w", err)
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("failed to read OSV.dev query response: %w", err)
		}
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("received unexpected status from the OSV.dev API: %s", resp.Status)
		}

		var result queryResponse
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("failed to decode OSV.dev query response: %w", err)
		}
		for _, vuln := range result.Vulns {
			if vuln.ID != "" {
				ids = append(ids, vuln.ID)
			}
		}

		if result.NextPageToken == "" {
			return ids, nil
		}
		query.PageToken = result.NextPageToken
	}
	return ids, nil
}

// finding returns the finding for one OSV.dev advisory of the given package.
func (v Verifier) finding(pkg pm.Package, advisoryID string) evaluation.Finding {
	if strings.HasPrefix(advisoryID, "MAL") {
		return evaluation.Finding{
			Verifier: v.Name(),
			Severity: evaluation.SeverityCritical,
			Text: fmt.Sprintf(
				"An OSV.dev malicious package advisory exists for package %s %s@%s:\n  * %s/%s",
				pkg.Ecosystem, pkg.Name, pkg.Version, osvVulnerabilityURLPrefix, advisoryID,
			),
		}
	}
	return evaluation.Finding{
		Verifier: v.Name(),
		Severity: evaluation.SeverityWarning,
		Text: fmt.Sprintf(
			"An OSV.dev advisory exists for package %s %s@%s:\n  * %s/%s",
			pkg.Ecosystem, pkg.Name, pkg.Version, osvVulnerabilityURLPrefix, advisoryID,
		),
	}
}
