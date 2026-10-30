// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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

// PyPIRequestKind describes the role of an HTTP request in the PyPI protocols.
// Metadata requests never need policy evaluation; artifact requests do.
type PyPIRequestKind uint8

const (
	PyPIRequestUnrelated PyPIRequestKind = iota
	PyPIRequestJSONAPI
	PyPIRequestSimpleAPI
	PyPIRequestCoreMetadata
	PyPIRequestArtifact
)

// PyPIRequestClassifierOptions describes index contexts known by the package
// manager integration. SimpleIndexURLs are project-list roots (the project
// name is the next path segment); DirectArtifactURLs are exact distribution
// URLs supplied directly on the command line or by configuration.
type PyPIRequestClassifierOptions struct {
	SimpleIndexURLs    []string
	DirectArtifactURLs []string
}

// PyPIRequestClassifier classifies requests within one package-manager run.
// Advertised artifact URLs remain the metadata cache's responsibility because
// they may be opaque and can point at an otherwise unknown CDN.
type PyPIRequestClassifier struct {
	simpleIndexes      []pyPISimpleIndex
	directArtifactURLs map[string]struct{}
}

type pyPISimpleIndex struct {
	match     url.URL
	discovery url.URL
}

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

// NewPyPIRequestClassifier creates a run-scoped classifier for configured
// custom index and direct-artifact contexts.
func NewPyPIRequestClassifier(options PyPIRequestClassifierOptions) (*PyPIRequestClassifier, error) {
	classifier := &PyPIRequestClassifier{directArtifactURLs: make(map[string]struct{})}
	for _, value := range options.SimpleIndexURLs {
		parsed, err := parsePyPIContextURL(value)
		if err != nil {
			return nil, fmt.Errorf("invalid PyPI Simple index URL: %w", err)
		}
		parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/"
		parsed.RawPath = ""
		parsed.Fragment = ""
		discovery := *parsed
		parsed.RawQuery, parsed.User = "", nil
		classifier.simpleIndexes = append(classifier.simpleIndexes, pyPISimpleIndex{match: *parsed, discovery: discovery})
	}
	for _, value := range options.DirectArtifactURLs {
		parsed, err := parsePyPIContextURL(value)
		if err != nil {
			return nil, fmt.Errorf("invalid PyPI direct artifact URL: %w", err)
		}
		classifier.directArtifactURLs[directPyPIURLKey(parsed)] = struct{}{}
	}
	return classifier, nil
}

func parsePyPIContextURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("expected an absolute HTTP(S) URL")
	}
	return parsed, nil
}

var defaultPyPIRequestClassifier = &PyPIRequestClassifier{}

// ClassifyPyPIRequest recognizes requests using the built-in PyPI and common
// Simple API layouts. Integrations with arbitrary bases use a run classifier.
func ClassifyPyPIRequest(method string, requestURL *url.URL) (PyPIRequestKind, PyPIArtifact) {
	return defaultPyPIRequestClassifier.ClassifyRequest(method, requestURL)
}

// ClassifyRequest recognizes PyPI metadata and distribution requests. A
// parseable archive is immediately trusted only on a supported registry host
// or at an explicitly configured direct URL. Configured custom indexes require
// exact advertisement through metadata discovery before evaluation.
func (classifier *PyPIRequestClassifier) ClassifyRequest(method string, requestURL *url.URL) (PyPIRequestKind, PyPIArtifact) {
	if requestURL == nil || (requestURL.Scheme != "http" && requestURL.Scheme != "https") {
		return PyPIRequestUnrelated, PyPIArtifact{}
	}
	cleanPath := path.Clean(requestURL.EscapedPath())
	host := strings.ToLower(requestURL.Hostname())
	_, configuredProject := classifier.configuredSimpleProject(requestURL)
	_, knownSimpleProject := PyPISimpleProject(requestURL)
	_, directArtifact := classifier.directArtifactURLs[directPyPIURLKey(requestURL)]
	directCoreMetadata := false
	if strings.HasSuffix(strings.ToLower(requestURL.Path), ".whl.metadata") {
		wheelURL := *requestURL
		wheelURL.Path = wheelURL.Path[:len(wheelURL.Path)-len(".metadata")]
		if strings.HasSuffix(strings.ToLower(wheelURL.RawPath), ".metadata") {
			wheelURL.RawPath = wheelURL.RawPath[:len(wheelURL.RawPath)-len(".metadata")]
		}
		_, directCoreMetadata = classifier.directArtifactURLs[directPyPIURLKey(&wheelURL)]
	}
	artifactContext := slices.Contains(pyPIRegistryDomains, host) || directArtifact || directCoreMetadata
	// Artifact parsing takes precedence over metadata path recognition: custom
	// indexes sometimes serve distributions beneath their Simple API base.
	if method == http.MethodGet {
		filename := path.Base(requestURL.EscapedPath())
		if strings.HasSuffix(strings.ToLower(filename), ".whl.metadata") {
			wheelFilename := filename[:len(filename)-len(".metadata")]
			if _, _, ok := ParsePyPIDistributionFilename(wheelFilename); ok && artifactContext {
				return PyPIRequestCoreMetadata, PyPIArtifact{}
			}
		}
		name, version, ok := ParsePyPIDistributionFilename(filename)
		if ok && artifactContext {
			return PyPIRequestArtifact, PyPIArtifact{
				Name: name, Version: version, Filename: artifactFilename(requestURL.String()),
				Source: canonicalPyPIURL(nil, requestURL.String()), RequestKey: pyPIURLRequestKey(nil, requestURL.String()),
			}
		}
	}
	if host == "pypi.org" && strings.HasPrefix(cleanPath, "/pypi/") && strings.HasSuffix(cleanPath, "/json") {
		return PyPIRequestJSONAPI, PyPIArtifact{}
	}
	if knownSimpleProject || configuredProject || cleanPath == "/simple" {
		return PyPIRequestSimpleAPI, PyPIArtifact{}
	}
	return PyPIRequestUnrelated, PyPIArtifact{}
}

// ClassifyResponse recognizes Simple API protocol evidence that is only known
// after receiving a response. Vendor media types are safe evidence; generic
// application/json and text/html are intentionally insufficient.
func (classifier *PyPIRequestClassifier) ClassifyResponse(method string, requestURL *url.URL, header http.Header) (PyPIRequestKind, PyPIArtifact) {
	kind, artifact := classifier.ClassifyRequest(method, requestURL)
	if kind != PyPIRequestUnrelated || method != http.MethodGet || requestURL == nil {
		return kind, artifact
	}
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if mediaType != "application/vnd.pypi.simple.v1+json" && mediaType != "application/vnd.pypi.simple.v1+html" {
		return PyPIRequestUnrelated, PyPIArtifact{}
	}
	if _, ok := simpleProjectFromLastPathSegment(requestURL); !ok {
		return PyPIRequestUnrelated, PyPIArtifact{}
	}
	return PyPIRequestSimpleAPI, PyPIArtifact{}
}

// SimpleProject returns the normalized project associated with a recognized
// Simple API endpoint, including configured arbitrary bases and response-only
// endpoints identified by their protocol media type.
func (classifier *PyPIRequestClassifier) SimpleProject(requestURL *url.URL, header http.Header) (string, bool) {
	if project, ok := PyPISimpleProject(requestURL); ok {
		return project, true
	}
	if project, ok := classifier.configuredSimpleProject(requestURL); ok {
		return project, true
	}
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if mediaType == "application/vnd.pypi.simple.v1+json" || mediaType == "application/vnd.pypi.simple.v1+html" {
		return simpleProjectFromLastPathSegment(requestURL)
	}
	return "", false
}

func (classifier *PyPIRequestClassifier) configuredSimpleProject(requestURL *url.URL) (string, bool) {
	if classifier == nil || requestURL == nil {
		return "", false
	}
	for index := range classifier.simpleIndexes {
		base := &classifier.simpleIndexes[index].match
		if !sameURLOrigin(base, requestURL) || !strings.HasPrefix(requestURL.Path, base.Path) {
			continue
		}
		remainder := strings.Trim(requestURL.Path[len(base.Path):], "/")
		if remainder == "" || strings.Contains(remainder, "/") {
			continue
		}
		decoded, err := url.PathUnescape(remainder)
		if err == nil && pyPIProjectName.MatchString(decoded) {
			return NormalizePyPIName(decoded), true
		}
	}
	return "", false
}

// MetadataDiscovery returns a filename-derived project hint and configured
// Simple endpoints that can prove whether the exact URL is a distribution.
// It deliberately does not return an artifact: the filename is never policy
// evidence unless metadata subsequently advertises the exact request URL.
func (classifier *PyPIRequestClassifier) MetadataDiscovery(requestURL *url.URL) (string, []url.URL, bool) {
	if classifier == nil || requestURL == nil || len(classifier.simpleIndexes) == 0 ||
		(requestURL.Scheme != "http" && requestURL.Scheme != "https") {
		return "", nil, false
	}
	filename := path.Base(requestURL.EscapedPath())
	name, _, ok := ParsePyPIDistributionFilename(filename)
	if !ok {
		return "", nil, false
	}
	endpoints := make([]url.URL, 0, len(classifier.simpleIndexes))
	for index := range classifier.simpleIndexes {
		endpoint := classifier.simpleIndexes[index].discovery
		endpoint.Path += url.PathEscape(name) + "/"
		endpoint.RawPath = ""
		endpoints = append(endpoints, endpoint)
	}
	return name, endpoints, true
}

func simpleProjectFromLastPathSegment(requestURL *url.URL) (string, bool) {
	if requestURL == nil {
		return "", false
	}
	segment, err := url.PathUnescape(path.Base(path.Clean(requestURL.EscapedPath())))
	if err != nil || !pyPIProjectName.MatchString(segment) {
		return "", false
	}
	return NormalizePyPIName(segment), true
}

func directPyPIURLKey(value *url.URL) string {
	if value == nil {
		return ""
	}
	withoutCredentials := *value
	withoutCredentials.User = nil
	return pyPIURLRequestKey(nil, withoutCredentials.String())
}

// PyPISimpleProject recognizes supported project-level Simple API paths while
// avoiding a broad match on arbitrary paths containing a "simple" segment.
func PyPISimpleProject(requestURL *url.URL) (string, bool) {
	if requestURL == nil {
		return "", false
	}
	segments := strings.Split(strings.Trim(path.Clean(requestURL.EscapedPath()), "/"), "/")
	var project string
	switch {
	case len(segments) == 2 && segments[0] == "simple":
		project = segments[1]
	case len(segments) == 5 && segments[0] == "api" && segments[1] == "pypi" && segments[3] == "simple":
		project = segments[4]
	case len(segments) == 6 && segments[0] == "artifactory" && segments[1] == "api" && segments[2] == "pypi" && segments[4] == "simple":
		project = segments[5]
	case len(segments) == 4 && segments[2] == "+simple":
		project = segments[3]
	default:
		return "", false
	}
	decoded, err := url.PathUnescape(project)
	if err != nil || !pyPIProjectName.MatchString(decoded) {
		return "", false
	}
	return NormalizePyPIName(decoded), true
}

// redactPyPIArtifactURL retains the artifact origin and path while removing
// fields commonly used for credentials in custom-index and signed CDN URLs.
func redactPyPIArtifactURL(value *url.URL) string {
	redacted := *value
	redacted.User = nil
	redacted.RawQuery = ""
	redacted.ForceQuery = false
	redacted.Fragment = ""
	return redacted.String()
}

func canonicalPyPIURL(base *url.URL, reference string) string {
	parsed := resolvePyPIURL(base, reference)
	if parsed == nil {
		return ""
	}
	return redactPyPIArtifactURL(parsed)
}

// pyPIURLRequestKey retains exact URL matching without keeping reversible
// credentials or query values in map keys that might appear in diagnostics.
func pyPIURLRequestKey(base *url.URL, reference string) string {
	parsed := resolvePyPIURL(base, reference)
	if parsed == nil {
		return ""
	}
	redacted := redactPyPIArtifactURL(parsed)
	user := ""
	if parsed.User != nil {
		user = parsed.User.String()
	}
	digest := sha256.Sum256([]byte(user + "\x00" + parsed.RawQuery))
	return fmt.Sprintf("%s\x00%x", redacted, digest)
}

func resolvePyPIURL(base *url.URL, reference string) *url.URL {
	parsed, err := url.Parse(reference)
	if err != nil {
		return nil
	}
	if base != nil {
		parsed = base.ResolveReference(parsed)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed
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
