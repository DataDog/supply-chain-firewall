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
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// pyPIRegistryDomains are the URL domains associated with the PyPI registry, ported from
// ecosystem.py's ECOSYSTEM.registry_domains in the Python reference.
var pyPIRegistryDomains = []string{"pypi.org", "files.pythonhosted.org", "pypi.python.org"}

// PyPIArtifact identifies the distribution requested by a package manager.
type PyPIArtifact struct {
	Name       string
	Version    string
	Filename   string
	Source     string
	RequestKey string
}

var (
	pyPINameSeparator = regexp.MustCompile(`[-_.]+`)
	// PEP 427 escapes distribution and version components before constructing a
	// wheel filename, so neither component contains a hyphen. The optional build
	// tag starts with a digit, followed by the three compatibility tags.
	pyPIWheelFilename = regexp.MustCompile(`^([A-Za-z0-9_.]+)-([A-Za-z0-9_.!+]+)(?:-([0-9][^-]*))?-([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)-([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)-([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\.whl$`)
	// Captures the public-version grammar from PEP 440. Canonicalization below
	// resolves the permitted alternate spellings and separators.
	pyPIVersion     = regexp.MustCompile(`(?i)^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]*))?(?:(?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]*)))?(?:[-_.]?(dev)[-_.]?([0-9]*))?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)
	pyPIProjectName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$`)
)

var pyPISdistExtensions = []string{
	".tar.lzma", ".tar.bz2", ".tar.gz", ".tar.lz", ".tar.xz", ".tar.z",
	".tbz", ".tgz", ".tlz", ".txz", ".tar", ".zip",
}

// NormalizePyPIName applies the project-name normalization specified by PEP
// 503: ASCII case-folding and replacement of every run of '-', '_' or '.' by
// one hyphen.
func NormalizePyPIName(name string) string {
	return pyPINameSeparator.ReplaceAllString(strings.ToLower(name), "-")
}

// ParsePyPIDistributionFilename parses a wheel or common source-distribution
// filename according to PEP 427/491 and PEP 625/440.
func ParsePyPIDistributionFilename(filename string) (name, version string, ok bool) {
	filename, err := url.PathUnescape(filename)
	if err != nil || filename == "" || strings.ContainsAny(filename, `/\\`) {
		return "", "", false
	}

	if match := pyPIWheelFilename.FindStringSubmatch(filename); match != nil {
		canonicalVersion, valid := canonicalPyPIVersion(match[2])
		if !valid {
			return "", "", false
		}
		return NormalizePyPIName(match[1]), canonicalVersion, true
	}

	stem := ""
	lower := strings.ToLower(filename)
	for _, extension := range pyPISdistExtensions {
		if strings.HasSuffix(lower, extension) {
			stem = filename[:len(filename)-len(extension)]
			break
		}
	}
	if stem == "" {
		return "", "", false
	}

	// PEP 625 specifies the last hyphen as the name/version separator. This is
	// also packaging.utils.parse_sdist_filename's behavior, so project-1-2 is
	// project-1 version 2 rather than project version 1.post2.
	if separator := strings.LastIndexByte(stem, '-'); separator > 0 {
		candidateName, candidateVersion := stem[:separator], stem[separator+1:]
		canonicalVersion, valid := canonicalPyPIVersion(candidateVersion)
		if pyPIProjectName.MatchString(candidateName) && valid {
			return NormalizePyPIName(candidateName), canonicalVersion, true
		}
	}

	// Some legacy sdists put a non-PEP-625 hyphen inside the version. Retain a
	// narrowly scoped fallback only when the standard last-hyphen parse failed.
	for separator := strings.IndexByte(stem, '-'); separator > 0; {
		candidateName, candidateVersion := stem[:separator], stem[separator+1:]
		canonicalVersion, valid := canonicalPyPIVersion(candidateVersion)
		if pyPIProjectName.MatchString(candidateName) && valid {
			return NormalizePyPIName(candidateName), canonicalVersion, true
		}
		next := strings.IndexByte(stem[separator+1:], '-')
		if next < 0 {
			break
		}
		separator += next + 1
	}
	return "", "", false
}

// canonicalPyPIVersion returns the canonical public form defined by PEP 440.
// It deliberately parses each component rather than using a permissive
// semver-like split: equivalent spellings must deduplicate to one version.
func canonicalPyPIVersion(version string) (string, bool) {
	match := pyPIVersion.FindStringSubmatch(version)
	if match == nil {
		return "", false
	}

	var canonical strings.Builder
	if epoch := canonicalNumber(match[1]); epoch != "" && epoch != "0" {
		canonical.WriteString(epoch)
		canonical.WriteByte('!')
	}
	release := strings.Split(match[2], ".")
	for index, segment := range release {
		if index > 0 {
			canonical.WriteByte('.')
		}
		canonical.WriteString(canonicalNumber(segment))
	}
	if match[3] != "" {
		canonical.WriteString(canonicalPrereleaseLabel(match[3]))
		canonical.WriteString(canonicalOptionalNumber(match[4]))
	}
	if match[5] != "" {
		canonical.WriteString(".post")
		canonical.WriteString(canonicalNumber(match[5]))
	} else if match[6] != "" {
		canonical.WriteString(".post")
		canonical.WriteString(canonicalOptionalNumber(match[7]))
	}
	if match[8] != "" {
		canonical.WriteString(".dev")
		canonical.WriteString(canonicalOptionalNumber(match[9]))
	}
	if match[10] != "" {
		canonical.WriteByte('+')
		local := pyPINameSeparator.Split(strings.ToLower(match[10]), -1)
		for index, segment := range local {
			if index > 0 {
				canonical.WriteByte('.')
			}
			if onlyDigits(segment) {
				segment = canonicalNumber(segment)
			}
			canonical.WriteString(segment)
		}
	}
	return canonical.String(), true
}

// PyPIVersionIdentity returns the PEP 440 equality identity for a version.
// Exact canonical release spelling is retained on PyPIArtifact.Version for
// registry lookup and reporting, while release trailing zeros are ignored here
// because PEP 440 compares missing release segments as zero.
func PyPIVersionIdentity(version string) string {
	canonical, valid := canonicalPyPIVersion(version)
	if !valid {
		return version
	}
	match := pyPIVersion.FindStringSubmatch(canonical)
	release := strings.Split(match[2], ".")
	for len(release) > 1 && release[len(release)-1] == "0" {
		release = release[:len(release)-1]
	}
	prefixLength := 0
	if match[1] != "" {
		prefixLength = len(match[1]) + 1
	}
	suffix := canonical[prefixLength+len(match[2]):]
	return canonical[:prefixLength] + strings.Join(release, ".") + suffix
}

func canonicalPrereleaseLabel(label string) string {
	switch strings.ToLower(label) {
	case "a", "alpha":
		return "a"
	case "b", "beta":
		return "b"
	default:
		return "rc"
	}
}

func canonicalOptionalNumber(value string) string {
	if value == "" {
		return "0"
	}
	return canonicalNumber(value)
}

func canonicalNumber(value string) string {
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return "0"
	}
	return value
}

func onlyDigits(value string) bool {
	return strings.Trim(value, "0123456789") == ""
}

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
	return resolvePyPIPublishDateWithClient(ctx, http.DefaultClient, name, version, source)
}

func resolvePyPIPublishDateWithClient(ctx context.Context, client *http.Client, name, version, source string) (time.Time, error) {
	if source != "" && !isPyPIRegistrySource(source) {
		return time.Time{}, nil
	}

	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to build PyPI request: %w", err)
	}

	resp, err := client.Do(req)
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

	filename := artifactFilename(source)
	if _, _, ok := ParsePyPIDistributionFilename(filename); !ok {
		filename = ""
	}
	return parsePyPIReleaseMetadataForArtifact(body, name, version, filename)
}

// ResolvePyPIPublishDateWithClient resolves an exact PyPI artifact using the
// supplied registry client, allowing future proxy adapters to honor their
// command-specific upstream without putting transport behavior in the adapter.
func ResolvePyPIPublishDateWithClient(ctx context.Context, client *http.Client, name, version, source string) (time.Time, error) {
	if client == nil {
		client = http.DefaultClient
	}
	return resolvePyPIPublishDateWithClient(ctx, client, name, version, source)
}

// parsePyPIReleaseMetadataForArtifact selects the upload timestamp for the
// exact requested file. When filename is empty (the legacy metadata-only call
// path), it retains the historical latest-file behavior.
func parsePyPIReleaseMetadataForArtifact(body []byte, name, version, filename string) (time.Time, error) {
	var metadata struct {
		Releases map[string][]struct {
			Filename          string `json:"filename"`
			URL               string `json:"url"`
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
		if filename != "" && release.Filename != filename && artifactFilename(release.URL) != filename {
			continue
		}
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
		if filename != "" {
			return time.Time{}, fmt.Errorf("no publication timestamp for file %s of version %s of package %s", filename, version, name)
		}
		return time.Time{}, fmt.Errorf("no publication timestamp for version %s of package %s", version, name)
	}

	return latest, nil
}

func artifactFilename(source string) string {
	if source == "" {
		return ""
	}
	u, err := url.Parse(source)
	if err != nil {
		return ""
	}
	filename, err := url.PathUnescape(path.Base(u.EscapedPath()))
	if err != nil {
		return ""
	}
	return filename
}
