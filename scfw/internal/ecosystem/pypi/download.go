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

func (e ProxyHandler) observeOpaqueDownload(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, bool, error) {
	if response.Request.Method != http.MethodGet {
		return nil, false, nil
	}
	_, direct := e.Classifier.directArtifactURLs[directPyPIURLKey(&response.Request.URL)]
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	kind, _ := e.Classifier.ClassifyRequest(response.Request.Method, &response.Request.URL)
	_, parameters, _ := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	_, _, distribution := ParseDistributionFilename(path.Base(parameters["filename"]))
	required := direct || distribution
	candidate := required || isDownloadMediaType(mediaType) || (mediaType == "" && kind == RequestUnrelated)
	// A conditional opaque response may refer to bytes held only in pip's
	// cache. Inspect an unconditional copy before returning the original 304.
	if response.StatusCode == http.StatusNotModified && (required || !IsMetadataContentType(response.Header)) {
		metadataKind, _, _ := e.classifyMetadataResponse(response)
		if !required && !isDownloadMediaType(mediaType) && (metadataKind == RequestJSONAPI || metadataKind == RequestSimpleAPI) {
			return nil, false, nil
		}
		_, _, metadata := e.Metadata.ProjectForURL(&response.Request.URL)
		if required || (e.Client != nil && (isDownloadMediaType(mediaType) || (!metadata && kind == RequestUnrelated))) {
			download, err := e.inspectFullDownload(ctx, response, required)
			return nil, download, err
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices || response.StatusCode == http.StatusNoContent || !candidate {
		return nil, false, nil
	}
	// Index HTML/JSON and Git protocol responses retain their streaming paths.
	if response.StatusCode == http.StatusPartialContent {
		download, err := e.inspectFullDownload(ctx, response, required)
		return nil, download, err
	}
	return &proxy.ResponseBodyHook{
		MaxBytes: MaxArtifactBytes,
		HandleFile: func(ctx context.Context, response proxy.Response, body *io.SectionReader) error {
			return e.evaluateDownloadedArchive(ctx, response, body, required)
		},
	}, true, nil
}

func isDownloadMediaType(mediaType string) bool {
	switch mediaType {
	case "application/octet-stream", "application/zip", "application/x-zip-compressed",
		"application/gzip", "application/x-gzip", "application/x-tar", "application/x-bzip2",
		"application/x-xz", "application/x-lzma":
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
	if !required && mediaType != "" && !isDownloadMediaType(mediaType) {
		// An archive-shaped project endpoint can initially look unrelated.
		// Keep the original 304's metadata classification and refresh path.
		return false, nil
	}
	if response.ContentLength > MaxArtifactBytes {
		return true, errors.New("python download exceeds inspection limit")
	}
	original.StatusCode, original.Header = response.StatusCode, response.Header
	return true, proxy.InspectReader(ctx, response.Body, MaxArtifactBytes, func(body *io.SectionReader) error {
		return e.evaluateDownloadedArchive(ctx, original, body, required)
	})
}

func (e ProxyHandler) evaluateDownloadedArchive(ctx context.Context, response proxy.Response, body *io.SectionReader, required bool) error {
	return inspectDecodedArchive(ctx, body, response.Header.Get("Content-Encoding"), func(body *io.SectionReader) error {
		artifact, found, err := inspectArchive(ctx, body)
		if err != nil {
			return err
		}
		if !found {
			if required {
				return errors.New("python download has no usable package metadata")
			}
			return nil
		}
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
