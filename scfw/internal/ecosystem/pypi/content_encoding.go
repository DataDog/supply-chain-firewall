// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// newContentDecoder decodes one HTTP content encoding. Callers retain their
// own decoded-body limits and choose the maximum Zstandard decoder memory.
func newContentDecoder(reader io.Reader, encoding string, maxMemory uint64) (io.Reader, func(), error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return reader, func() {}, nil
	case "gzip", "x-gzip":
		decoder, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, err
		}
		return decoder, func() { _ = decoder.Close() }, nil
	case "deflate":
		decoder, err := zlib.NewReader(reader)
		if err != nil {
			return nil, nil, err
		}
		return decoder, func() { _ = decoder.Close() }, nil
	case "br":
		return brotli.NewReader(reader), func() {}, nil
	case "zstd":
		decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxMemory))
		if err != nil {
			return nil, nil, err
		}
		return decoder, decoder.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported PyPI content encoding %q", encoding)
	}
}
