// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html"
)

// MaxMetadataBytes bounds both encoded and decoded metadata retained from
// an index response. Callers must handle oversized or unsupported responses
// before exposing uninspected metadata to the package manager.
const MaxMetadataBytes = 8 << 20

var errPyPIMetadataTooLarge = fmt.Errorf("PyPI metadata exceeds %d bytes", MaxMetadataBytes)

// MetadataCache stores exact per-distribution upload times observed in
// PyPI JSON API and Simple API responses during one package-manager run.
type MetadataCache struct {
	mutex     sync.RWMutex
	records   map[string]pyPIMetadataRecord
	aliases   map[string]pyPIMetadataRecord
	ambiguous map[string]bool
	endpoints map[string]pyPIMetadataEndpoint
	observed  map[string]bool
	discovery map[string]*pyPIMetadataDiscovery
}

type pyPIMetadataRecord struct {
	artifact Artifact
	date     time.Time
}

type pyPIMetadataEndpoint struct {
	url       url.URL
	project   string
	header    http.Header
	tentative bool
}

type pyPIMetadataDiscovery struct {
	done chan struct{}
	err  error
}

// Register records a metadata endpoint for later independent refresh.
func (cache *MetadataCache) Register(requestURL url.URL, requestHeader http.Header) {
	cache.registerEndpoint(requestURL, requestHeader)
}

// RegisterProject records a Simple endpoint whose arbitrary base was
// configured by an integration or established by PyPI protocol media type.
func (cache *MetadataCache) RegisterProject(requestURL url.URL, project string, requestHeader http.Header) {
	cache.registerProjectEndpoint(requestURL, NormalizeName(project), requestHeader, false)
}

// RegisterProjectCandidate retains the possible project behind an ambiguous
// archive-shaped redirect without treating the destination's binary as metadata.
func (cache *MetadataCache) RegisterProjectCandidate(requestURL url.URL, project string, requestHeader http.Header) {
	cache.registerProjectEndpoint(requestURL, NormalizeName(project), requestHeader, true)
}

// ProjectForURL returns the Simple project registered for this exact endpoint,
// including redirect destinations. Tentative projects need response media-type
// evidence before their successful response bodies can be treated as metadata.
func (cache *MetadataCache) ProjectForURL(requestURL *url.URL) (project string, tentative, found bool) {
	if requestURL == nil {
		return "", false, false
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	endpoint, found := cache.endpoints[key]
	return endpoint.project, endpoint.tentative, found
}

// IsMetadataContentType recognizes JSON/HTML representations within a known
// or tentative metadata context. It does not identify an arbitrary URL as PyPI.
func IsMetadataContentType(header http.Header) bool {
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") ||
		mediaType == "text/html" || strings.HasSuffix(mediaType, "+html")
}

// RegisterRedirect carries a known Simple project's context to its redirect
// destination. Credentials are captured from the destination's actual request,
// never copied from the redirecting endpoint.
func (cache *MetadataCache) RegisterRedirect(requestURL url.URL, location string) {
	project, tentative, found := cache.ProjectForURL(&requestURL)
	if !found || location == "" {
		return
	}
	target, err := requestURL.Parse(location)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return
	}
	// Clients move URL userinfo into Authorization before sending the request
	// through the proxy. Match that wire-visible URL without retaining or
	// forwarding credentials from Location for independent metadata refreshes.
	target.User = nil
	// HTTP clients send an origin-only URL with a root path on the wire.
	if target.Path == "" {
		target.Path = "/"
	}
	cache.registerProjectEndpoint(*target, project, nil, tentative)
}

// PublishDate returns an observed upload time for this exact distribution.
func (cache *MetadataCache) PublishDate(artifact Artifact) (time.Time, bool) {
	key := artifact.RequestKey
	if key == "" {
		key = pyPIURLRequestKey(nil, artifact.Source)
	}
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	record, found := cache.recordForKey(key)
	if !found || record.date.IsZero() || record.artifact.Name != artifact.Name || VersionIdentity(record.artifact.Version) != VersionIdentity(artifact.Version) {
		return time.Time{}, false
	}
	return record.date, true
}

// ArtifactForURL resolves an advertised, possibly opaque, distribution URL to
// the identity supplied by its Simple or JSON metadata.
func (cache *MetadataCache) ArtifactForURL(requestURL *url.URL) (Artifact, bool) {
	if requestURL == nil {
		return Artifact{}, false
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	record, found := cache.recordForKey(key)
	cache.mutex.RUnlock()
	if !found {
		return Artifact{}, false
	}
	return record.artifact, true
}

// recordForKey requires the cache mutex to be held by the caller.
func (cache *MetadataCache) recordForKey(key string) (pyPIMetadataRecord, bool) {
	if cache.ambiguous[key] {
		return pyPIMetadataRecord{}, false
	}
	record, found := cache.records[key]
	if !found {
		record, found = cache.aliases[key]
	}
	return record, found
}

// IsCoreMetadataURL reports whether a request is the PEP 658/714 metadata
// sidecar for an advertised wheel. Core metadata must pass through without
// evaluating it as a distribution download.
func (cache *MetadataCache) IsCoreMetadataURL(requestURL *url.URL) bool {
	if requestURL == nil || !strings.HasSuffix(strings.ToLower(requestURL.Path), ".metadata") {
		return false
	}
	wheelURL := *requestURL
	wheelURL.Path = wheelURL.Path[:len(wheelURL.Path)-len(".metadata")]
	if wheelURL.RawPath != "" && strings.HasSuffix(strings.ToLower(wheelURL.RawPath), ".metadata") {
		wheelURL.RawPath = wheelURL.RawPath[:len(wheelURL.RawPath)-len(".metadata")]
	}
	artifact, found := cache.ArtifactForURL(&wheelURL)
	return found && strings.HasSuffix(strings.ToLower(artifact.Filename), ".whl")
}

// Discover refreshes configured Simple endpoints for a filename-derived
// project hint. Success only means the metadata was fetched; the caller must
// still require ArtifactForURL to match the exact request URL before treating
// it as a distribution. Concurrent hints for one project share the refresh.
func (cache *MetadataCache) Discover(
	ctx context.Context,
	client *http.Client,
	project string,
	endpoints []url.URL,
	artifactURL *url.URL,
	artifactHeader http.Header,
) error {
	if client == nil || len(endpoints) == 0 {
		return errors.New("PyPI metadata discovery is unavailable")
	}
	project = NormalizeName(project)
	cache.mutex.Lock()
	if cache.discovery == nil {
		cache.discovery = make(map[string]*pyPIMetadataDiscovery)
	}
	discovery, exists := cache.discovery[project]
	if !exists {
		discovery = &pyPIMetadataDiscovery{done: make(chan struct{})}
		cache.discovery[project] = discovery
	}
	cache.mutex.Unlock()

	if exists {
		select {
		case <-discovery.done:
			return discovery.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	var refreshErrors []error
	for _, endpoint := range endpoints {
		var discoveryHeader http.Header
		if sameURLOrigin(&endpoint, artifactURL) {
			discoveryHeader = artifactHeader
		}
		cache.RegisterProject(endpoint, project, discoveryHeader)
		if err := cache.Refresh(ctx, client, endpoint); err != nil {
			refreshErrors = append(refreshErrors, err)
		}
	}
	discovery.err = errors.Join(refreshErrors...)
	cache.mutex.Lock()
	if discovery.err != nil && cache.discovery[project] == discovery {
		delete(cache.discovery, project)
	}
	close(discovery.done)
	cache.mutex.Unlock()
	return discovery.err
}

// Observe parses a complete metadata response supplied by the proxy or an
// independent refresh. The caller owns reading and buffering the encoded body.
func (cache *MetadataCache) Observe(requestURL url.URL, header http.Header, encoded []byte) error {
	if len(encoded) > MaxMetadataBytes {
		logPyPIMetadataLimit(requestURL)
		return errPyPIMetadataTooLarge
	}
	body, err := decodePyPIMetadata(encoded, header.Get("Content-Encoding"))
	if err != nil {
		if errors.Is(err, errPyPIMetadataTooLarge) {
			logPyPIMetadataLimit(requestURL)
		}
		return err
	}
	project := cache.metadataProject(&requestURL)
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	var parseErr error
	if strings.HasSuffix(mediaType, "+json") || mediaType == "application/json" || (mediaType == "" && firstNonSpace(body) == '{') {
		parseErr = cache.observeJSON(body, &requestURL, project)
	} else if mediaType == "text/html" || strings.HasSuffix(mediaType, "+html") || mediaType == "" {
		parseErr = cache.observeHTML(body, &requestURL, project)
	} else {
		return fmt.Errorf("unsupported PyPI metadata content type %q", header.Get("Content-Type"))
	}
	if parseErr != nil {
		return parseErr
	}
	// A redirected endpoint can have a path naming a different project. Do
	// not replace the original request's context with a guess from that path.
	if _, _, found := cache.ProjectForURL(&requestURL); !found {
		cache.registerEndpoint(requestURL, nil)
	}
	cache.markObserved(requestURL)
	return nil
}

func logPyPIMetadataLimit(requestURL url.URL) {
	slog.Warn("PyPI metadata exceeds size limit", "url", canonicalPyPIURL(nil, requestURL.String()), "limit_bytes", MaxMetadataBytes)
}

// Resolve project context before HTML base elements change link resolution.
func (cache *MetadataCache) metadataProject(requestURL *url.URL) string {
	if project, _, found := cache.ProjectForURL(requestURL); found {
		return project
	}
	if project, found := SimpleProject(requestURL); found {
		return project
	}
	segments := strings.Split(strings.Trim(path.Clean(requestURL.Path), "/"), "/")
	if strings.EqualFold(requestURL.Hostname(), "pypi.org") && (len(segments) == 3 || len(segments) == 4) &&
		segments[0] == "pypi" && segments[len(segments)-1] == "json" && pyPIProjectName.MatchString(segments[1]) {
		return NormalizeName(segments[1])
	}
	return ""
}

func decodePyPIMetadata(encoded []byte, contentEncoding string) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(encoded)
	var closeReader func()
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "", "identity":
	case "gzip", "x-gzip":
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("open gzip PyPI metadata: %w", err)
		}
		reader = gzipReader
		closeReader = func() { _ = gzipReader.Close() }
	case "deflate":
		zlibReader, err := zlib.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("open deflate PyPI metadata: %w", err)
		}
		reader = zlibReader
		closeReader = func() { _ = zlibReader.Close() }
	case "br":
		reader = brotli.NewReader(reader)
	case "zstd":
		decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxMetadataBytes*2))
		if err != nil {
			return nil, fmt.Errorf("open Zstandard PyPI metadata: %w", err)
		}
		reader = decoder
		closeReader = decoder.Close
	default:
		return nil, fmt.Errorf("unsupported PyPI metadata content encoding %q", contentEncoding)
	}
	if closeReader != nil {
		defer closeReader()
	}
	body, err := io.ReadAll(io.LimitReader(reader, MaxMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decode PyPI metadata: %w", err)
	}
	if len(body) > MaxMetadataBytes {
		return nil, errPyPIMetadataTooLarge
	}
	return body, nil
}

func firstNonSpace(body []byte) byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return 0
	}
	return trimmed[0]
}

func (cache *MetadataCache) observeJSON(body []byte, base *url.URL, project string) error {
	var metadata struct {
		Name string `json:"name"`
		Info struct {
			Name string `json:"name"`
		} `json:"info"`
		Releases map[string][]struct {
			Filename          string `json:"filename"`
			URL               string `json:"url"`
			UploadTimeISO8601 string `json:"upload_time_iso_8601"`
		} `json:"releases"`
		URLs []struct {
			Filename          string `json:"filename"`
			URL               string `json:"url"`
			UploadTimeISO8601 string `json:"upload_time_iso_8601"`
		} `json:"urls"`
		Files []struct {
			Filename   string `json:"filename"`
			URL        string `json:"url"`
			UploadTime string `json:"upload-time"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return fmt.Errorf("parse PyPI metadata JSON: %w", err)
	}
	if project == "" {
		if pyPIProjectName.MatchString(metadata.Name) {
			project = NormalizeName(metadata.Name)
		} else if pyPIProjectName.MatchString(metadata.Info.Name) {
			project = NormalizeName(metadata.Info.Name)
		}
	}
	for _, releases := range metadata.Releases {
		for _, release := range releases {
			filename := release.Filename
			if filename == "" {
				filename = artifactFilename(release.URL)
			}
			cache.store(base, filename, release.URL, release.UploadTimeISO8601, project)
		}
	}
	for _, release := range metadata.URLs {
		filename := release.Filename
		if filename == "" {
			filename = artifactFilename(release.URL)
		}
		cache.store(base, filename, release.URL, release.UploadTimeISO8601, project)
	}
	for _, file := range metadata.Files {
		filename := file.Filename
		if filename == "" {
			filename = artifactFilename(canonicalPyPIURL(base, file.URL))
		}
		cache.store(base, filename, file.URL, file.UploadTime, project)
	}
	return nil
}

func (cache *MetadataCache) observeHTML(body []byte, base *url.URL, project string) error {
	base = pyPIHTMLBaseURL(body, base)
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && err != io.EOF {
				return fmt.Errorf("parse PyPI Simple HTML: %w", err)
			}
			return nil
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if !strings.EqualFold(token.Data, "a") {
				continue
			}
			var href, uploadTime string
			for _, attribute := range token.Attr {
				switch strings.ToLower(attribute.Key) {
				case "href":
					href = attribute.Val
				case "data-upload-time":
					// This is a nonstandard compatibility extension. Standard
					// Simple HTML has no upload date and falls back to JSON.
					uploadTime = attribute.Val
				}
			}
			cache.store(base, artifactFilename(canonicalPyPIURL(base, href)), href, uploadTime, project)
		}
	}
}

// pyPIHTMLBaseURL finds the first base element with an href, as installers do
// when resolving Simple HTML links. Scan the whole document before processing
// anchors so that a base element also applies to links preceding it.
func pyPIHTMLBaseURL(body []byte, fallback *url.URL) *url.URL {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return fallback
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "base" {
				continue
			}
			for _, attribute := range token.Attr {
				if attribute.Key == "href" {
					if resolved := resolvePyPIURL(fallback, attribute.Val); resolved != nil {
						return resolved
					}
					return fallback
				}
			}
		}
	}
}

func (cache *MetadataCache) store(base *url.URL, filename, reference, uploadTime, project string) {
	name, version, ok := parsePyPIDistributionFilename(filename, project)
	source := canonicalPyPIURL(base, reference)
	requestKey := pyPIURLRequestKey(base, reference)
	if !ok || source == "" || requestKey == "" {
		return
	}
	var date time.Time
	if uploadTime != "" {
		date, _ = time.Parse(time.RFC3339Nano, uploadTime)
	}
	artifact := Artifact{Name: name, Version: version, Filename: filename, Source: source, RequestKey: requestKey}
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cache.records == nil {
		cache.records = make(map[string]pyPIMetadataRecord)
	}
	record := pyPIMetadataRecord{artifact: artifact, date: date}
	stored := cache.storeRecord(cache.records, requestKey, record)
	// HTTP userinfo is authentication for a resource identified by its
	// scheme/host/path/query; clients normally move it into Authorization before
	// the proxy observes the URL. Retain a userinfo-free alias only while that
	// resource maps to one package identity. Explicit query variants remain
	// distinct, and conflicting credential variants make the alias ambiguous.
	resolved := resolvePyPIURL(base, reference)
	if resolved != nil && resolved.User != nil {
		resolved.User = nil
		aliasKey := pyPIURLRequestKey(nil, resolved.String())
		if !stored {
			cache.markAmbiguous(aliasKey)
			return
		}
		cache.storeAlias(aliasKey, record)
	}
}

func (cache *MetadataCache) storeAlias(key string, record pyPIMetadataRecord) {
	if cache.aliases == nil {
		cache.aliases = make(map[string]pyPIMetadataRecord)
	}
	cache.storeRecord(cache.aliases, key, record)
}

// storeRecord merges evidence for an exact request key or its wire-visible
// alias. Identity conflicts invalidate both paths for the remainder of the run.
func (cache *MetadataCache) storeRecord(records map[string]pyPIMetadataRecord, key string, record pyPIMetadataRecord) bool {
	if key == "" || cache.ambiguous[key] {
		return false
	}
	for _, existingRecords := range []map[string]pyPIMetadataRecord{cache.records, cache.aliases} {
		if existing, found := existingRecords[key]; found {
			if !samePyPIArtifactIdentity(existing.artifact, record.artifact) {
				cache.markAmbiguous(key)
				return false
			}
			if record.date.IsZero() {
				record.date = existing.date
			}
		}
	}
	// An exact record and a userinfo-free alias can coexist for the same key.
	// Keep both views of matching evidence current so neither shadows a newer
	// valid timestamp with an older one.
	for _, existingRecords := range []map[string]pyPIMetadataRecord{cache.records, cache.aliases} {
		if existing, found := existingRecords[key]; found {
			existing.date = record.date
			existingRecords[key] = existing
		}
	}
	record.artifact.RequestKey = key
	records[key] = record
	return true
}

func (cache *MetadataCache) markAmbiguous(key string) {
	delete(cache.records, key)
	delete(cache.aliases, key)
	if cache.ambiguous == nil {
		cache.ambiguous = make(map[string]bool)
	}
	cache.ambiguous[key] = true
}

func samePyPIArtifactIdentity(first, second Artifact) bool {
	return first.Name == second.Name && VersionIdentity(first.Version) == VersionIdentity(second.Version) &&
		first.Filename == second.Filename
}

func (cache *MetadataCache) registerEndpoint(requestURL url.URL, requestHeader http.Header) {
	project, ok := SimpleProject(&requestURL)
	if !ok {
		return
	}
	cache.registerProjectEndpoint(requestURL, project, requestHeader, false)
}

func (cache *MetadataCache) registerProjectEndpoint(requestURL url.URL, project string, requestHeader http.Header, tentative bool) {
	if !pyPIProjectName.MatchString(project) {
		return
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.Lock()
	if cache.endpoints == nil {
		cache.endpoints = make(map[string]pyPIMetadataEndpoint)
	}
	endpoint, found := cache.endpoints[key]
	if !found || endpoint.project != project {
		endpoint.tentative = tentative
	} else {
		endpoint.tentative = endpoint.tentative && tentative
	}
	endpoint.url, endpoint.project = requestURL, project
	if captured := refreshRequestHeaders(requestHeader); len(captured) > 0 {
		endpoint.header = captured
	}
	cache.endpoints[key] = endpoint
	cache.mutex.Unlock()
}

func (cache *MetadataCache) markObserved(requestURL url.URL) {
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.Lock()
	if cache.observed == nil {
		cache.observed = make(map[string]bool)
	}
	cache.observed[key] = true
	cache.mutex.Unlock()
}

// HasObserved reports whether this exact metadata endpoint has already
// supplied a successfully parsed response during the run.
func (cache *MetadataCache) HasObserved(requestURL url.URL) bool {
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.observed[key]
}

// Refresh fetches one metadata endpoint independently and observes its body.
func (cache *MetadataCache) Refresh(ctx context.Context, client *http.Client, requestURL url.URL) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return errors.New("build PyPI metadata refresh request")
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	endpoint := cache.endpoints[key]
	refreshHeader := endpoint.header.Clone()
	cache.mutex.RUnlock()
	if refreshHeader != nil {
		request.Header = refreshHeader
	}
	request.Header.Set("Accept", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.9, text/html;q=0.8")
	refreshClient := metadataRefreshClient(client, &requestURL)
	response, err := refreshClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// Transport errors can embed the credentialed request URL. Keep the
		// failure actionable without exposing it in diagnostics or reports.
		return errors.New("PyPI metadata refresh request failed")
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("refresh PyPI metadata: unexpected status %s", response.Status)
	}
	if endpoint.tentative && !IsMetadataContentType(response.Header) {
		// A cached archive can also return 304 at a Simple-shaped URL. Its
		// independent refresh must confirm metadata before inspecting the body.
		return nil
	}
	responseURL := &requestURL
	if response.Request != nil && response.Request.URL != nil {
		responseURL = response.Request.URL
	}
	// Independent refresh redirects do not pass through the proxy's hooks.
	// Carry the original project without copying its authentication headers.
	if project := cache.metadataProject(&requestURL); project != "" {
		cache.RegisterProject(*responseURL, project, nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxMetadataBytes+1))
	if err != nil {
		return fmt.Errorf("read PyPI metadata refresh: %w", err)
	}
	if err := cache.Observe(*responseURL, response.Header, body); err != nil {
		return fmt.Errorf("observe PyPI metadata refresh: %w", err)
	}
	cache.markObserved(requestURL)
	return nil
}

// ResolvePublishDate refreshes previously observed Simple endpoints for the
// artifact's project and returns the date for its exact advertised source.
func (cache *MetadataCache) ResolvePublishDate(ctx context.Context, client *http.Client, artifact Artifact) (time.Time, error) {
	if date, found := cache.PublishDate(artifact); found {
		return date, nil
	}
	cache.mutex.RLock()
	var endpoints []url.URL
	for _, endpoint := range cache.endpoints {
		if endpoint.project == artifact.Name {
			endpoints = append(endpoints, endpoint.url)
		}
	}
	cache.mutex.RUnlock()
	var refreshErrors []error
	for _, endpoint := range endpoints {
		if err := cache.Refresh(ctx, client, endpoint); err != nil {
			refreshErrors = append(refreshErrors, err)
			continue
		}
		if date, found := cache.PublishDate(artifact); found {
			return date, nil
		}
	}
	return time.Time{}, errors.Join(refreshErrors...)
}

func refreshRequestHeaders(header http.Header) http.Header {
	captured := make(http.Header)
	for name, values := range header {
		switch http.CanonicalHeaderKey(name) {
		case "Accept", "Accept-Encoding", "Connection", "If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since",
			"Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Range", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
			continue
		}
		captured[name] = append([]string(nil), values...)
	}
	return captured
}

func metadataRefreshClient(client *http.Client, origin *url.URL) *http.Client {
	refreshClient := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	refreshClient.Transport = metadataRefreshTransport{base: transport, origin: origin}
	// The package manager's request headers are the only credentials refresh is
	// allowed to reuse. A client jar could add unrelated cookies after redirect
	// policy runs, so do not carry it into this short-lived client copy.
	refreshClient.Jar = nil
	refreshClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		request.Header.Del("Referer")
		if len(via) >= 10 {
			return errors.New("stopped after 10 PyPI metadata redirects")
		}
		return nil
	}
	return &refreshClient
}

type metadataRefreshTransport struct {
	base   http.RoundTripper
	origin *url.URL
}

func (transport metadataRefreshTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header = request.Header.Clone()
	request.Header.Del("Referer")
	if !sameURLOrigin(transport.origin, request.URL) {
		accept := request.Header.Get("Accept")
		request.Header = make(http.Header)
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		request.URL.User = nil
	}
	return transport.base.RoundTrip(request)
}

func sameURLOrigin(first, second *url.URL) bool {
	if first == nil || second == nil || !strings.EqualFold(first.Scheme, second.Scheme) || !strings.EqualFold(first.Hostname(), second.Hostname()) {
		return false
	}
	return effectiveURLPort(first) == effectiveURLPort(second)
}

func effectiveURLPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(value.Scheme, "http") {
		return "80"
	}
	return ""
}

// ResolveArtifactPublishDate resolves one distribution's upload time, preferring
// observed metadata, then independently refreshed metadata, and finally fallback.
func (cache *MetadataCache) ResolveArtifactPublishDate(
	ctx context.Context,
	client *http.Client,
	artifact Artifact,
	fallback func(context.Context, string, string, string) (time.Time, error),
) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	publishDate, found := cache.PublishDate(artifact)
	var publishErr error
	if !found && client != nil {
		publishDate, publishErr = cache.ResolvePublishDate(ctx, client, artifact)
		if isContextError(publishErr) {
			return time.Time{}, publishErr
		}
		found = !publishDate.IsZero()
	}
	if !found {
		fallbackDate, fallbackErr := fallback(ctx, artifact.Name, artifact.Version, artifact.Source)
		if !fallbackDate.IsZero() || fallbackErr != nil || publishErr == nil {
			publishDate, publishErr = fallbackDate, fallbackErr
		}
	}
	if isContextError(publishErr) {
		return time.Time{}, publishErr
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if publishErr == nil && publishDate.IsZero() {
		publishErr = errors.New("publication date unavailable")
	}
	return publishDate, publishErr
}
