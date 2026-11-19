// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// RequestKind describes the role of an HTTP request in the npm registry
// protocol. Only tarball downloads install code and need policy evaluation.
type RequestKind uint8

const (
	RequestUnrelated RequestKind = iota
	RequestRegistryAPI
	RequestTarball
	// RequestOpaqueTarball is a tarball-shaped download outside the registry
	// layout, such as a direct URL or a GitHub codeload archive. Its identity
	// comes from the package.json inside the archive.
	RequestOpaqueTarball
)

// Artifact identifies the package version a tarball request downloads.
type Artifact struct {
	Name     string
	Version  string
	Filename string
	// Source is the requested URL without credentials, query or fragment.
	Source string
	// PackumentURL is the registry document describing every version of Name.
	PackumentURL url.URL
	// authorization is the tarball request's Authorization header, reused only
	// toward the tarball's origin when fetching the packument.
	authorization string
}

// ClassifierOptions describes npm registries known by the package manager
// integration, so registry API paths beneath their base paths are recognized.
type ClassifierOptions struct {
	RegistryURLs []string
}

// Classifier classifies npm registry requests within one package-manager run.
type Classifier struct {
	registries []url.URL
	// opaqueRedirects holds redirect targets of opaque tarball requests, keyed
	// by URL without credentials, so suffix-less targets are still inspected.
	opaqueRedirects sync.Map
}

// semverPattern is the regular expression recommended by https://semver.org.
var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// NewClassifier returns a classifier that also recognizes the given registries.
func NewClassifier(options ClassifierOptions) (*Classifier, error) {
	classifier := &Classifier{}
	for _, value := range options.RegistryURLs {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, errors.New("invalid npm registry URL: expected an absolute HTTP(S) URL")
		}
		registry := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path, RawPath: parsed.RawPath}
		if !strings.HasSuffix(registry.Path, "/") {
			registry.Path += "/"
			registry.RawPath = ""
		}
		classifier.registries = append(classifier.registries, registry)
	}
	return classifier, nil
}

// publicRegistryHosts are served over https by the public npm registry;
// lockfiles name either one regardless of the configured registry.
var publicRegistryHosts = []string{"registry.npmjs.org", "registry.yarnpkg.com"}

// isKnownRegistry reports whether requestURL shares the origin of a configured
// or public registry. The base path is ignored: registries serve tarballs
// outside it on the same origin.
func (classifier *Classifier) isKnownRegistry(requestURL *url.URL) bool {
	scheme, host := strings.ToLower(requestURL.Scheme), strings.ToLower(requestURL.Hostname())
	port := effectivePort(requestURL)
	for _, public := range publicRegistryHosts {
		if scheme == "https" && host == public && port == "443" {
			return true
		}
	}
	for index := range classifier.registries {
		registry := &classifier.registries[index]
		if strings.EqualFold(registry.Scheme, scheme) && strings.EqualFold(registry.Hostname(), host) && effectivePort(registry) == port {
			return true
		}
	}
	return false
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "http") {
		return "80"
	}
	return "443"
}

// Classify recognizes npm registry requests from the URL path alone: clients
// disagree on Accept headers, so those are never evidence. Tarballs are
// recognized on any host, so an unknown host cannot opt out of evaluation.
func (classifier *Classifier) Classify(requestURL *url.URL) (RequestKind, Artifact) {
	if requestURL == nil || requestURL.Host == "" || (requestURL.Scheme != "http" && requestURL.Scheme != "https") {
		return RequestUnrelated, Artifact{}
	}
	escapedPath := normalizeEscapedPath(requestURL.EscapedPath())
	relativePath := escapedPath
	for _, registry := range classifier.registries {
		base := normalizeEscapedPath(registry.EscapedPath())
		if strings.EqualFold(registry.Scheme, requestURL.Scheme) && strings.EqualFold(registry.Host, requestURL.Host) &&
			strings.HasPrefix(escapedPath, base) {
			relativePath = "/" + strings.TrimPrefix(escapedPath, base)
			break
		}
	}

	if artifact, ok := parseTarball(requestURL, escapedPath); ok {
		return RequestTarball, artifact
	}
	if isOpaqueTarball(requestURL.Host, escapedPath) {
		return RequestOpaqueTarball, Artifact{Source: redactURL(requestURL)}
	}
	segments := strings.Split(strings.TrimPrefix(relativePath, "/"), "/")
	if segments[0] == "-" {
		return RequestRegistryAPI, Artifact{}
	}
	return RequestUnrelated, Artifact{}
}

// normalizeEscapedPath returns the path registries actually serve for a
// request: percent-encoded unreserved characters (RFC 3986 section 6.2.2.2) and
// encoded slashes are decoded, then dot segments and repeated slashes are
// resolved, so none of them can hide a tarball or change its identity. A
// scoped name's slash becomes literal; parseTarball re-encodes it for the
// packument URL. Other escapes, such as %40, are kept.
func normalizeEscapedPath(escapedPath string) string {
	var decoded strings.Builder
	decoded.Grow(len(escapedPath))
	for index := 0; index < len(escapedPath); index++ {
		character := escapedPath[index]
		if character == '%' && index+2 < len(escapedPath) {
			value, err := strconv.ParseUint(escapedPath[index+1:index+3], 16, 8)
			if err == nil && (value == '/' || isUnreserved(byte(value))) {
				character = byte(value)
				index += 2
			}
		}
		decoded.WriteByte(character)
	}
	normalized := path.Clean("/" + decoded.String())
	// Keep a trailing slash: configured registry bases rely on it for prefix matching.
	if strings.HasSuffix(decoded.String(), "/") && normalized != "/" {
		normalized += "/"
	}
	return normalized
}

func isUnreserved(character byte) bool {
	return 'a' <= character && character <= 'z' || 'A' <= character && character <= 'Z' ||
		'0' <= character && character <= '9' || strings.IndexByte("-._~", character) >= 0
}

// parseTarball parses "<base>/<name>/-/<last name segment>-<version>.tgz",
// where a scoped name's slash may be literal or percent-encoded. GitLab names
// scoped tarballs after the full scoped name instead: "<name>-<version>.tgz".
func parseTarball(requestURL *url.URL, escapedPath string) (Artifact, bool) {
	separator := strings.LastIndex(escapedPath, "/-/")
	if separator < 0 {
		return Artifact{}, false
	}
	escapedFilename := escapedPath[separator+len("/-/"):]
	if escapedFilename == "" {
		return Artifact{}, false
	}

	segments := strings.Split(escapedPath[:separator], "/")
	escapedName, baseSegments := segments[len(segments)-1], segments[:len(segments)-1]
	// Private registries such as Artifactory percent-encode the scope's "@".
	if len(segments) >= 3 && isScopeSegment(segments[len(segments)-2]) {
		escapedName = segments[len(segments)-2] + "/" + escapedName
		baseSegments = segments[:len(segments)-2]
	}
	name, err := url.PathUnescape(escapedName)
	if err != nil {
		return Artifact{}, false
	}
	unscoped, ok := unscopedName(name)
	if !ok {
		return Artifact{}, false
	}

	filename, err := url.PathUnescape(escapedFilename)
	if err != nil || !strings.HasSuffix(filename, ".tgz") {
		return Artifact{}, false
	}
	nameVersion, found := strings.CutPrefix(filename, unscoped+"-")
	if !found || strings.Contains(escapedFilename, "/") {
		nameVersion, found = strings.CutPrefix(filename, name+"-")
		if !found || !strings.HasPrefix(name, "@") {
			return Artifact{}, false
		}
	}
	version := strings.TrimSuffix(nameVersion, ".tgz")
	if !semverPattern.MatchString(version) {
		return Artifact{}, false
	}

	rawPackumentPath := strings.Join(baseSegments, "/") + "/" + url.PathEscape(name)
	packumentPath, err := url.PathUnescape(rawPackumentPath)
	if err != nil {
		return Artifact{}, false
	}
	return Artifact{
		Name:         name,
		Version:      version,
		Filename:     filename,
		Source:       redactURL(requestURL),
		PackumentURL: url.URL{Scheme: requestURL.Scheme, Host: requestURL.Host, Path: packumentPath, RawPath: rawPackumentPath},
	}, true
}

// isOpaqueTarball recognizes downloads npm-compatible clients unpack as
// packages: tarball filenames, GitHub codeload archives (which npm fetches for
// github:, git+https://github.com and git+ssh://git@github.com dependencies),
// and GitHub Packages downloads, whose URLs carry no suffix.
func isOpaqueTarball(host, escapedPath string) bool {
	lower := strings.ToLower(escapedPath)
	if strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") {
		return true
	}
	hostname := strings.ToLower(host)
	if name, _, found := strings.Cut(hostname, ":"); found {
		hostname = name
	}
	switch hostname {
	case "codeload.github.com":
		segments := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")
		return len(segments) >= 4 && segments[0] != "" && segments[1] != "" && segments[2] == "tar.gz" && segments[3] != ""
	case "npm.pkg.github.com":
		return strings.HasPrefix(escapedPath, "/download/")
	}
	return false
}

func isScopeSegment(escapedSegment string) bool {
	segment, err := url.PathUnescape(escapedSegment)
	return err == nil && strings.HasPrefix(segment, "@")
}

// unscopedName returns the part of a valid package name that prefixes its
// tarball filenames: the whole name, or the part after "@scope/".
func unscopedName(name string) (string, bool) {
	if !strings.HasPrefix(name, "@") {
		return name, name != "" && !strings.Contains(name, "/")
	}
	scope, unscoped, found := strings.Cut(name, "/")
	if !found || scope == "@" || unscoped == "" || strings.Contains(unscoped, "/") {
		return "", false
	}
	return unscoped, true
}

// redactURL renders u without user information, query or fragment, any of
// which may carry registry credentials.
func redactURL(u *url.URL) string {
	redacted := *u
	redacted.User = nil
	redacted.RawQuery = ""
	redacted.ForceQuery = false
	redacted.Fragment = ""
	redacted.RawFragment = ""
	return redacted.String()
}
