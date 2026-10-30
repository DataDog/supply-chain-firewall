// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html"
)

// maxPyPIMetadataBytes bounds both encoded and decoded metadata retained from
// an index response. Oversized or unsupported responses simply leave the cache
// empty, causing the artifact request path to use its independent lookup.
const maxPyPIMetadataBytes = 8 << 20

// PyPIMetadataCache stores exact per-distribution upload times observed in
// PyPI JSON API and Simple API responses during one package-manager run.
type PyPIMetadataCache struct {
	mutex     sync.RWMutex
	records   map[string]pyPIMetadataRecord
	aliases   map[string]pyPIMetadataRecord
	ambiguous map[string]bool
	endpoints map[string]pyPIMetadataEndpoint
	observed  map[string]bool
	discovery map[string]*pyPIMetadataDiscovery
}

type pyPIMetadataRecord struct {
	artifact PyPIArtifact
	date     time.Time
}

type pyPIMetadataEndpoint struct {
	url     url.URL
	project string
	header  http.Header
}

type pyPIMetadataDiscovery struct {
	done chan struct{}
	err  error
}

// Register records a metadata endpoint for later independent refresh.
func (cache *PyPIMetadataCache) Register(requestURL url.URL, requestHeader http.Header) {
	cache.registerEndpoint(requestURL, requestHeader)
}

// RegisterProject records a Simple endpoint whose arbitrary base was
// configured by an integration or established by PyPI protocol media type.
func (cache *PyPIMetadataCache) RegisterProject(requestURL url.URL, project string, requestHeader http.Header) {
	cache.registerProjectEndpoint(requestURL, NormalizePyPIName(project), requestHeader)
}

// PublishDate returns an observed upload time for this exact distribution.
func (cache *PyPIMetadataCache) PublishDate(artifact PyPIArtifact) (time.Time, bool) {
	key := artifact.RequestKey
	if key == "" {
		key = pyPIURLRequestKey(nil, artifact.Source)
	}
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	record, found := cache.records[key]
	if !found || record.date.IsZero() || record.artifact.Name != artifact.Name || PyPIVersionIdentity(record.artifact.Version) != PyPIVersionIdentity(artifact.Version) {
		return time.Time{}, false
	}
	return record.date, true
}

// ArtifactForURL resolves an advertised, possibly opaque, distribution URL to
// the identity supplied by its Simple or JSON metadata.
func (cache *PyPIMetadataCache) ArtifactForURL(requestURL *url.URL) (PyPIArtifact, bool) {
	if requestURL == nil {
		return PyPIArtifact{}, false
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	record, found := cache.records[key]
	if !found && !cache.ambiguous[key] {
		record, found = cache.aliases[key]
	}
	cache.mutex.RUnlock()
	if !found {
		return PyPIArtifact{}, false
	}
	return record.artifact, true
}

// IsCoreMetadataURL reports whether a request is the PEP 658/714 metadata
// sidecar for an advertised wheel. Core metadata must pass through without
// evaluating it as a distribution download.
func (cache *PyPIMetadataCache) IsCoreMetadataURL(requestURL *url.URL) bool {
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
func (cache *PyPIMetadataCache) Discover(
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
	project = NormalizePyPIName(project)
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

// Observe returns a bounded streaming sink for one successful metadata
// response. The caller can mirror response bytes into it without changing the
// response delivered to the package manager. Closing parses and caches any
// exact upload times found.
func (cache *PyPIMetadataCache) Observe(requestURL url.URL, header http.Header) io.WriteCloser {
	cache.registerEndpoint(requestURL, nil)
	return &pyPIMetadataObserver{
		cache:           cache,
		requestURL:      requestURL,
		contentType:     header.Get("Content-Type"),
		contentEncoding: header.Get("Content-Encoding"),
	}
}

type pyPIMetadataObserver struct {
	cache           *PyPIMetadataCache
	requestURL      url.URL
	contentType     string
	contentEncoding string
	buffer          bytes.Buffer
	truncated       bool
}

func (observer *pyPIMetadataObserver) Write(data []byte) (int, error) {
	remaining := maxPyPIMetadataBytes - observer.buffer.Len()
	if remaining > 0 {
		write := len(data)
		if write > remaining {
			write = remaining
		}
		_, _ = observer.buffer.Write(data[:write])
	}
	if len(data) > remaining {
		observer.truncated = true
	}
	// Observation must never apply backpressure through a short write.
	return len(data), nil
}

func (observer *pyPIMetadataObserver) Close() error {
	if observer.truncated {
		return fmt.Errorf("PyPI metadata exceeds %d bytes", maxPyPIMetadataBytes)
	}
	body, err := decodePyPIMetadata(observer.buffer.Bytes(), observer.contentEncoding)
	if err != nil {
		return err
	}
	mediaType, _, _ := mime.ParseMediaType(observer.contentType)
	var parseErr error
	if strings.HasSuffix(mediaType, "+json") || mediaType == "application/json" || (mediaType == "" && firstNonSpace(body) == '{') {
		parseErr = observer.cache.observeJSON(body, &observer.requestURL)
	} else if mediaType == "text/html" || strings.HasSuffix(mediaType, "+html") || mediaType == "" {
		parseErr = observer.cache.observeHTML(body, &observer.requestURL)
	} else {
		return fmt.Errorf("unsupported PyPI metadata content type %q", observer.contentType)
	}
	if parseErr != nil {
		return parseErr
	}
	observer.cache.markObserved(observer.requestURL)
	return nil
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
		decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxPyPIMetadataBytes*2))
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
	body, err := io.ReadAll(io.LimitReader(reader, maxPyPIMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decode PyPI metadata: %w", err)
	}
	if len(body) > maxPyPIMetadataBytes {
		return nil, fmt.Errorf("decoded PyPI metadata exceeds %d bytes", maxPyPIMetadataBytes)
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

func (cache *PyPIMetadataCache) observeJSON(body []byte, base *url.URL) error {
	var metadata struct {
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
	for _, releases := range metadata.Releases {
		for _, release := range releases {
			filename := release.Filename
			if filename == "" {
				filename = artifactFilename(release.URL)
			}
			cache.store(base, filename, release.URL, release.UploadTimeISO8601)
		}
	}
	for _, release := range metadata.URLs {
		filename := release.Filename
		if filename == "" {
			filename = artifactFilename(release.URL)
		}
		cache.store(base, filename, release.URL, release.UploadTimeISO8601)
	}
	for _, file := range metadata.Files {
		filename := file.Filename
		if filename == "" {
			filename = artifactFilename(canonicalPyPIURL(base, file.URL))
		}
		cache.store(base, filename, file.URL, file.UploadTime)
	}
	return nil
}

func (cache *PyPIMetadataCache) observeHTML(body []byte, base *url.URL) error {
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
			cache.store(base, artifactFilename(canonicalPyPIURL(base, href)), href, uploadTime)
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

func (cache *PyPIMetadataCache) store(base *url.URL, filename, reference, uploadTime string) {
	name, version, ok := ParsePyPIDistributionFilename(filename)
	source := canonicalPyPIURL(base, reference)
	requestKey := pyPIURLRequestKey(base, reference)
	if !ok || source == "" || requestKey == "" {
		return
	}
	var date time.Time
	if uploadTime != "" {
		date, _ = time.Parse(time.RFC3339Nano, uploadTime)
	}
	artifact := PyPIArtifact{Name: name, Version: version, Filename: filename, Source: source, RequestKey: requestKey}
	cache.mutex.Lock()
	if cache.records == nil {
		cache.records = make(map[string]pyPIMetadataRecord)
	}
	record := pyPIMetadataRecord{artifact: artifact, date: date}
	cache.records[requestKey] = record
	// HTTP userinfo is authentication for a resource identified by its
	// scheme/host/path/query; clients normally move it into Authorization before
	// the proxy observes the URL. Retain a userinfo-free alias only while that
	// resource maps to one package identity. Explicit query variants remain
	// distinct, and conflicting credential variants make the alias ambiguous.
	resolved := resolvePyPIURL(base, reference)
	if resolved != nil && resolved.User != nil {
		resolved.User = nil
		cache.storeAlias(pyPIURLRequestKey(nil, resolved.String()), record)
	}
	cache.mutex.Unlock()
}

func (cache *PyPIMetadataCache) storeAlias(key string, record pyPIMetadataRecord) {
	if key == "" || cache.ambiguous[key] {
		return
	}
	if cache.aliases == nil {
		cache.aliases = make(map[string]pyPIMetadataRecord)
	}
	if existing, found := cache.aliases[key]; found && !samePyPIArtifactIdentity(existing.artifact, record.artifact) {
		delete(cache.aliases, key)
		if cache.ambiguous == nil {
			cache.ambiguous = make(map[string]bool)
		}
		cache.ambiguous[key] = true
		return
	}
	cache.aliases[key] = record
}

func samePyPIArtifactIdentity(first, second PyPIArtifact) bool {
	return first.Name == second.Name && PyPIVersionIdentity(first.Version) == PyPIVersionIdentity(second.Version) &&
		first.Filename == second.Filename
}

func (cache *PyPIMetadataCache) registerEndpoint(requestURL url.URL, requestHeader http.Header) {
	project, ok := PyPISimpleProject(&requestURL)
	if !ok {
		return
	}
	cache.registerProjectEndpoint(requestURL, project, requestHeader)
}

func (cache *PyPIMetadataCache) registerProjectEndpoint(requestURL url.URL, project string, requestHeader http.Header) {
	if !pyPIProjectName.MatchString(project) {
		return
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.Lock()
	if cache.endpoints == nil {
		cache.endpoints = make(map[string]pyPIMetadataEndpoint)
	}
	endpoint := cache.endpoints[key]
	endpoint.url, endpoint.project = requestURL, project
	if captured := refreshRequestHeaders(requestHeader); len(captured) > 0 {
		endpoint.header = captured
	}
	cache.endpoints[key] = endpoint
	cache.mutex.Unlock()
}

func (cache *PyPIMetadataCache) markObserved(requestURL url.URL) {
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
func (cache *PyPIMetadataCache) HasObserved(requestURL url.URL) bool {
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.observed[key]
}

// Refresh fetches one metadata endpoint independently and observes its body.
func (cache *PyPIMetadataCache) Refresh(ctx context.Context, client *http.Client, requestURL url.URL) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return errors.New("build PyPI metadata refresh request")
	}
	key := pyPIURLRequestKey(nil, requestURL.String())
	cache.mutex.RLock()
	refreshHeader := cache.endpoints[key].header.Clone()
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
	responseURL := &requestURL
	if response.Request != nil && response.Request.URL != nil {
		responseURL = response.Request.URL
	}
	observer := cache.Observe(*responseURL, response.Header)
	if _, err := io.Copy(observer, io.LimitReader(response.Body, maxPyPIMetadataBytes+1)); err != nil {
		return fmt.Errorf("read PyPI metadata refresh: %w", err)
	}
	if err := observer.Close(); err != nil {
		return fmt.Errorf("observe PyPI metadata refresh: %w", err)
	}
	cache.markObserved(requestURL)
	return nil
}

// ResolvePublishDate refreshes previously observed Simple endpoints for the
// artifact's project and returns the date for its exact advertised source.
func (cache *PyPIMetadataCache) ResolvePublishDate(ctx context.Context, client *http.Client, artifact PyPIArtifact) (time.Time, error) {
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
