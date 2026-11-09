// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// RequestKind describes the role of an HTTP request in the npm registry
// protocol. Only tarball downloads install code and need policy evaluation.
type RequestKind uint8

const (
	RequestUnrelated RequestKind = iota
	RequestRegistryAPI
	RequestTarball
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
	segments := strings.Split(strings.TrimPrefix(relativePath, "/"), "/")
	if segments[0] == "-" {
		return RequestRegistryAPI, Artifact{}
	}
	return RequestUnrelated, Artifact{}
}

// normalizeEscapedPath returns the equivalent path registries actually serve:
// percent-encoded unreserved characters are decoded (RFC 3986 section 6.2.2.2)
// and repeated slashes collapse, so neither can hide a tarball. Other escapes,
// notably a scoped name's %2F, are kept.
func normalizeEscapedPath(escapedPath string) string {
	var normalized strings.Builder
	normalized.Grow(len(escapedPath))
	var previous byte
	for index := 0; index < len(escapedPath); index++ {
		character := escapedPath[index]
		if character == '%' && index+2 < len(escapedPath) {
			if value, err := strconv.ParseUint(escapedPath[index+1:index+3], 16, 8); err == nil && isUnreserved(byte(value)) {
				character = byte(value)
				index += 2
			}
		}
		if character == '/' && previous == '/' {
			continue
		}
		normalized.WriteByte(character)
		previous = character
	}
	return normalized.String()
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
