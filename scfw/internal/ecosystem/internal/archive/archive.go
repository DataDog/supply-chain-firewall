// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package archive provides bounded, extraction-free inspection helpers for
// downloaded package archives.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	// MaxArtifactBytes bounds wire and HTTP-decoded downloads.
	MaxArtifactBytes int64 = 512 << 20
	// MaxExpandedBytes bounds the decompressed archive stream.
	MaxExpandedBytes int64 = 1 << 30
	// MaxMetadataBytes bounds a package metadata entry.
	MaxMetadataBytes int64 = 1 << 20
	// MaxEntries bounds the number of archive entries.
	MaxEntries = 10000
)

// ErrLimit reports an archive exceeding an inspection limit.
var ErrLimit = errors.New("archive exceeds inspection limit")

// ContextReader stops reading once its context ends.
type ContextReader struct {
	Ctx    context.Context
	Reader io.Reader
}

func (reader ContextReader) Read(buffer []byte) (int, error) {
	if err := reader.Ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(buffer)
}

// NewZstdReader bounds decoder memory so a large declared window cannot
// exhaust memory before any limit applies.
func NewZstdReader(reader io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
}

// InspectDecoded removes HTTP content encodings and passes the decoded,
// size-bounded body to inspect.
func InspectDecoded(ctx context.Context, body *io.SectionReader, encoding string, inspect func(*io.SectionReader) error) error {
	if encoding == "" || strings.EqualFold(strings.TrimSpace(encoding), "identity") {
		return inspect(body)
	}
	var reader io.Reader = body
	encodings := strings.Split(strings.ToLower(encoding), ",")
	if len(encodings) > 4 {
		return errors.New("too many download content encodings")
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
			decoder, err := NewZstdReader(reader)
			if err != nil {
				return err
			}
			defer decoder.Close()
			reader = decoder
		default:
			return errors.New("unsupported download content encoding")
		}
	}
	return proxy.InspectReader(ctx, reader, MaxArtifactBytes, inspect)
}

// WalkTAR calls visit for each entry of a TAR stream, bounding the entry count
// and the expanded size. Entry bodies are read only through the visited reader.
func WalkTAR(ctx context.Context, reader io.Reader, visit func(*tar.Header, io.Reader) error) error {
	limited := &io.LimitedReader{R: ContextReader{ctx, reader}, N: MaxExpandedBytes + 1}
	archive := tar.NewReader(limited)
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			if limited.N <= 0 {
				return ErrLimit
			}
			return nil
		}
		if err != nil {
			return err
		}
		if entries >= MaxEntries || header.Size > limited.N {
			return ErrLimit
		}
		if err := visit(header, archive); err != nil {
			return err
		}
	}
}

// FullDownloadHeaders keeps representation selection and origin credentials
// while removing conditional, range, and proxy connection state for a full GET.
func FullDownloadHeaders(header http.Header) http.Header {
	captured := make(http.Header)
	for name, values := range header {
		switch http.CanonicalHeaderKey(name) {
		case "Connection", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since",
			"Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Range", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
			continue
		}
		captured[name] = append([]string(nil), values...)
	}
	return captured
}
