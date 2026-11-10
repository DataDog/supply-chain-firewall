// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// ObserveResponseHeaders selects bounded file inspection for opaque downloads
// and delegates registry metadata to the existing JSON/HTML response handling.
func (e ProxyHandler) ObserveResponseHeaders(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	if hook, download, err := e.observeOpaqueDownload(ctx, response); download || err != nil {
		return hook, err
	}
	return e.ObserveMetadataHeaders(ctx, response)
}

// directPyPIURLKey matches explicit download URLs without retaining credentials.
func directPyPIURLKey(value *url.URL) string {
	if value == nil {
		return ""
	}
	withoutCredentials := *value
	withoutCredentials.User = nil
	return pyPIURLRequestKey(nil, withoutCredentials.String())
}

// Archive URL inspection is opt-in for managers that accept opaque source
// filenames. Discovering downloads at the response boundary covers requirements
// files, stdin, workspace members and expanded URLs without parsing those inputs.
func (c *RequestClassifier) archiveURLCandidate(value *url.URL) bool {
	if !c.inspectArchiveURLs {
		return false
	}
	if source, found := c.archiveRedirects.Load(directPyPIURLKey(value)); found && source.(archiveSource).candidate {
		return true
	}
	filename := strings.ToLower(strings.TrimRight(value.Path, "/"))
	for _, suffix := range append([]string{".whl"}, pyPISdistExtensions...) {
		if strings.HasSuffix(filename, suffix) {
			return true
		}
	}
	return false
}

func (e ProxyHandler) observeOpaqueDownload(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, bool, error) {
	if response.Request.Method != http.MethodGet {
		return nil, false, nil
	}
	_, direct := e.Classifier.directArtifactURLs[directPyPIURLKey(&response.Request.URL)]
	archiveURL := e.Classifier.archiveURLCandidate(&response.Request.URL)
	source := e.Classifier.archiveSource(response.Request.URL)
	direct = direct || source.required
	if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != http.StatusNotModified {
		e.Classifier.recordArchiveRedirect(response, source, archiveURL, direct)
	}

	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	kind, _ := e.Classifier.ClassifyRequest(response.Request.Method, &response.Request.URL)
	_, parameters, _ := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	_, _, distribution := ParseDistributionFilename(path.Base(parameters["filename"]))
	required := direct || distribution
	candidate := required || archiveURL || isDownloadMediaType(mediaType) || (mediaType == "" && kind == RequestUnrelated)
	// A conditional opaque response may refer to bytes held only in pip's
	// cache. Inspect an unconditional copy before returning the original 304.
	if response.StatusCode == http.StatusNotModified && (required || archiveURL || !IsMetadataContentType(response.Header)) {
		metadataKind, _, _ := e.classifyMetadataResponse(response)
		if !required && !archiveURL && !isDownloadMediaType(mediaType) && (metadataKind == RequestJSONAPI || metadataKind == RequestSimpleAPI) {
			return nil, false, nil
		}
		_, _, metadata := e.Metadata.ProjectForURL(&response.Request.URL)
		if required || archiveURL || (e.Client != nil && (isDownloadMediaType(mediaType) || (!metadata && kind == RequestUnrelated))) {
			download, err := e.inspectFullDownload(ctx, response, required)
			return nil, download, err
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices || response.StatusCode == http.StatusNoContent || !candidate {
		return nil, false, nil
	}
	// Ordinary index and Git responses retain their streaming paths.
	if response.StatusCode == http.StatusPartialContent {
		download, err := e.inspectFullDownload(ctx, response, required)
		return nil, download, err
	}
	return &proxy.ResponseBodyHook{
		MaxBytes: MaxArtifactBytes,
		HandleFile: func(ctx context.Context, response proxy.Response, body *io.SectionReader) error {
			return e.evaluateDownloadedArchive(ctx, response, body, required, archiveInspection{header: response.Header})
		},
	}, true, nil
}

func isDownloadMediaType(mediaType string) bool {
	switch mediaType {
	case "application/octet-stream", "application/zip", "application/x-zip-compressed",
		"application/gzip", "application/x-gzip", "application/x-tar", "application/x-bzip2",
		"application/x-xz", "application/x-lzma", "application/zstd", "application/x-zstd":
		return true
	}
	return false
}

func (e ProxyHandler) inspectFullDownload(ctx context.Context, original proxy.Response, required bool) (bool, error) {
	if e.Client == nil {
		return true, errors.New("cannot identify partial or cached Python download")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, original.Request.URL.String(), nil)
	if err != nil {
		return true, err
	}
	request.Header = refreshRequestHeaders(original.Request.Header)
	client := metadataRefreshClient(e.Client, &original.Request.URL)
	response, err := client.Do(request)
	if err != nil {
		return true, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return true, errors.New("could not inspect complete Python download")
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if !required && !e.Classifier.archiveURLCandidate(&original.Request.URL) && mediaType != "" && !isDownloadMediaType(mediaType) {
		// An archive-shaped project endpoint can initially look unrelated.
		// Keep the original 304's metadata classification and refresh path.
		return false, nil
	}
	if response.ContentLength > MaxArtifactBytes {
		return true, errors.New("python download exceeds inspection limit")
	}
	selection := archiveInspection{header: original.Header}
	if original.StatusCode == http.StatusNotModified {
		// Pip's cache may contain older MIME/disposition headers. The adapter
		// must reject competing interpretations when those headers are unknown.
		selection.header, selection.cachedHeaders = response.Header, true
	}
	original.StatusCode, original.Header = response.StatusCode, response.Header
	return true, proxy.InspectReader(ctx, response.Body, MaxArtifactBytes, func(body *io.SectionReader) error {
		return e.evaluateDownloadedArchive(ctx, original, body, required, selection)
	})
}

type archiveInspection struct {
	header        http.Header
	cachedHeaders bool
}

func (e ProxyHandler) evaluateDownloadedArchive(ctx context.Context, response proxy.Response, body *io.SectionReader, required bool, selection archiveInspection) error {
	foundPackage := false
	encoding := response.Header.Get("Content-Encoding")
	if e.Classifier.retainArchiveContentEncoding {
		encoding = ""
	}
	err := inspectDecodedArchive(ctx, body, encoding, func(body *io.SectionReader) error {
		artifact, found, err := e.inspectDownloadArchive(ctx, response, body, required, selection)
		if err != nil {
			return err
		}
		if !found {
			if required {
				return errors.New("python download has no usable package metadata")
			}
			return nil
		}
		foundPackage = true
		artifact.Filename = artifactFilename(response.Request.URL.String())
		artifact.Source = canonicalPyPIURL(nil, response.Request.URL.String())
		artifact.RequestKey = pyPIURLRequestKey(nil, response.Request.URL.String())
		if err := e.EvaluateArtifact(ctx, artifact); err != nil {
			if isContextError(err) {
				return err
			}
			return errors.Join(proxy.ErrResponseRejected, err)
		}
		return nil
	})
	if err != nil || foundPackage {
		return err
	}
	// A Simple/JSON endpoint may itself end in an archive suffix. Sniffing
	// must not consume the metadata UV will use to select its actual download.
	hook, err := e.ObserveMetadataHeaders(ctx, response)
	if err != nil || hook == nil || hook.Handle == nil {
		return err
	}
	if body.Size() > hook.MaxBytes {
		return errors.New("python metadata exceeds inspection limit")
	}
	response.Body, err = io.ReadAll(io.NewSectionReader(body, 0, body.Size()))
	if err != nil {
		return err
	}
	return hook.Handle(ctx, response)
}

func inspectDecodedArchive(ctx context.Context, body *io.SectionReader, encoding string, inspect func(*io.SectionReader) error) error {
	if encoding == "" || strings.EqualFold(strings.TrimSpace(encoding), "identity") {
		return inspect(body)
	}
	var reader io.Reader = body
	encodings := strings.Split(strings.ToLower(encoding), ",")
	if len(encodings) > 4 {
		return errors.New("too many Python download content encodings")
	}
	for index := len(encodings) - 1; index >= 0; index-- {
		switch strings.TrimSpace(encodings[index]) {
		case "identity":
		case "gzip", "x-gzip":
			decoder, err := gzip.NewReader(reader)
			if err != nil {
				return err
			}
			defer func() { _ = decoder.Close() }()
			reader = decoder
		case "deflate":
			decoder, err := zlib.NewReader(reader)
			if err != nil {
				return err
			}
			defer func() { _ = decoder.Close() }()
			reader = decoder
		case "br":
			reader = brotli.NewReader(reader)
		case "zstd":
			decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
			if err != nil {
				return err
			}
			defer decoder.Close()
			reader = decoder
		default:
			return errors.New("unsupported Python download content encoding")
		}
	}
	return proxy.InspectReader(ctx, reader, MaxArtifactBytes, inspect)
}

// A redirect must retain the name used by the manager before following it.
// Colliding origins are rejected at inspection instead of choosing arbitrarily.
type archiveSource struct {
	url                            url.URL
	filename                       string
	candidate, required, ambiguous bool
}

func (c *RequestClassifier) archiveSource(value url.URL) archiveSource {
	if source, found := c.archiveRedirects.Load(directPyPIURLKey(&value)); found {
		return source.(archiveSource)
	}
	return archiveSource{url: value}
}

func (c *RequestClassifier) recordArchiveRedirect(response proxy.Response, source archiveSource, candidate, required bool) {
	target, err := response.Request.URL.Parse(response.Header.Get("Location"))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return
	}
	source.candidate = source.candidate || candidate
	source.required = source.required || required
	key := directPyPIURLKey(target)
	if previous, loaded := c.archiveRedirects.LoadOrStore(key, source); loaded {
		old := previous.(archiveSource)
		if directPyPIURLKey(&old.url) != directPyPIURLKey(&source.url) || old.filename != source.filename || source.ambiguous {
			old.ambiguous = true
			old.candidate = old.candidate || source.candidate
			old.required = old.required || source.required
			c.archiveRedirects.Store(key, old)
		}
	}
}

func (e ProxyHandler) inspectDownloadArchive(ctx context.Context, response proxy.Response, body *io.SectionReader, required bool, selection archiveInspection) (Artifact, bool, error) {
	if e.Classifier.selectArchive == nil {
		return inspectArchive(ctx, body)
	}
	probe := sync.OnceValues(func() (ArchiveSignatures, error) { return probeArchive(ctx, body) })
	signatures, err := probe()
	if err != nil {
		return Artifact{}, false, err
	}
	if !required && !signatures.ZIP && signatures.TAR == ArchiveUnknown {
		// Archive-shaped index endpoints still need normal JSON/HTML handling.
		return Artifact{}, false, nil
	}
	source := e.Classifier.archiveSource(response.Request.URL)
	if source.ambiguous {
		return Artifact{}, false, errors.New("ambiguous Python download origin")
	}
	format, err := e.Classifier.selectArchive(ArchiveInput{RegistryFilename: source.filename, CachedHeaders: selection.cachedHeaders, URL: source.url, ResponseURL: response.Request.URL, Header: selection.header, Probe: probe})
	if err != nil {
		return Artifact{}, false, err
	}
	packageDownload := required || e.Classifier.archiveURLCandidate(&response.Request.URL)
	if format == ArchiveUnknown {
		if !packageDownload {
			// A compressed requirements file or other non-package response is
			// not an unknown package archive merely because it has a signature.
			_, found, err := inspectArchive(ctx, body)
			if err != nil || !found {
				return Artifact{}, false, err
			}
		}
		return Artifact{}, false, errors.New("cannot determine package manager archive format")
	}
	if directPyPIURLKey(&source.url) != directPyPIURLKey(&response.Request.URL) {
		// A later direct request to the same target cannot be distinguished from a
		// redirected request. Reject if both source names permit different readers.
		alternative, alternativeErr := e.Classifier.selectArchive(ArchiveInput{CachedHeaders: selection.cachedHeaders, URL: response.Request.URL, ResponseURL: response.Request.URL, Header: selection.header, Probe: probe})
		if alternativeErr == nil && alternative != ArchiveUnknown && alternative != format {
			return Artifact{}, false, errors.New("conflicting Python archive formats across redirect")
		}
	}
	artifact, found, err := inspectArchiveFormat(ctx, body, format)
	if err == nil && !found && packageDownload {
		err = errors.New("python download has no usable package metadata")
	}
	return artifact, found, err
}

func (e ProxyHandler) observeArtifactHeaders(ctx context.Context, response proxy.Response, filename string) (*proxy.ResponseBodyHook, error) {
	if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != http.StatusNotModified {
		kind, _, _ := e.classifyMetadataResponse(response)
		if kind == RequestSimpleAPI || kind == RequestJSONAPI {
			return e.ObserveMetadataHeaders(ctx, response)
		}
		source := e.Classifier.archiveSource(response.Request.URL)
		source.filename = filename
		e.Classifier.recordArchiveRedirect(response, source, true, true)
	}
	return e.ObserveMetadataHeaders(ctx, response)
}
