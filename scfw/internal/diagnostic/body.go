// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package diagnostic

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html"
)

// MetadataBody decodes only an already-read, bounded candidate. It never reads
// or drains the network. The ecosystem must positively identify metadata.
func MetadataBody(header http.Header, prefix []byte, complete bool, eligible func([]byte) bool, redactor *Redactor) map[string]any {
	if !complete {
		return map[string]any{"omitted": "response incomplete or exceeds 64 KiB candidate limit"}
	}
	body, ok := decodeCandidate(header.Get("Content-Encoding"), prefix)
	if !ok || !utf8.Valid(body) {
		return map[string]any{"omitted": "unsupported, invalid or oversized encoded metadata candidate"}
	}
	if !eligible(body) {
		return map[string]any{"omitted": "not validated ecosystem metadata; package contents are excluded"}
	}
	var document any
	var text string
	if json.Unmarshal(body, &document) == nil {
		encoded, err := json.MarshalIndent(redactor.Value(document), "", "  ")
		if err != nil {
			return map[string]any{"omitted": "metadata could not be sanitized"}
		}
		text = string(encoded)
	} else {
		var safe bool
		text, safe = sanitizeHTML(body, redactor)
		if !safe {
			return map[string]any{"omitted": "unsafe or oversized HTML metadata"}
		}
	}
	truncated := len(text) > MaxText
	if truncated {
		text = text[:MaxText]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return map[string]any{"kind": "metadata", "text": text, "truncated": truncated}
}

func sanitizeHTML(body []byte, redactor *Redactor) (string, bool) {
	tokens := html.NewTokenizer(bytes.NewReader(body))
	var output strings.Builder
	for {
		kind := tokens.Next()
		if kind == html.ErrorToken {
			return output.String(), tokens.Err() == io.EOF
		}
		if kind == html.CommentToken {
			continue
		}
		token := tokens.Token()
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken {
			switch token.Data {
			case "script", "style", "input", "form", "iframe", "object":
				return "", false
			}
			for index := range token.Attr {
				attr := &token.Attr[index]
				if attr.Key == "href" || attr.Key == "src" {
					attr.Val = redactor.Reference(attr.Val)
				} else if secretKey.MatchString(attr.Key) {
					attr.Val = redacted
				} else {
					attr.Val = redactor.Text(attr.Val)
				}
			}
		}
		if kind == html.TextToken {
			token.Data = redactor.Text(token.Data)
		}
		output.WriteString(token.String())
		if output.Len() > 64<<10 {
			return "", false
		}
	}
}

func decodeCandidate(encoding string, body []byte) ([]byte, bool) {
	if len(body) > 64<<10 {
		return nil, false
	}
	var reader io.Reader = bytes.NewReader(body)
	var closer io.Closer
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
	case "gzip", "x-gzip":
		decoded, err := gzip.NewReader(reader)
		if err != nil {
			return nil, false
		}
		reader, closer = decoded, decoded
	case "deflate":
		decoded, err := zlib.NewReader(reader)
		if err != nil {
			return nil, false
		}
		reader, closer = decoded, decoded
	case "br":
		reader = brotli.NewReader(reader)
	case "zstd":
		decoded, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(8<<20), zstd.WithDecoderMaxWindow(8<<20))
		if err != nil {
			return nil, false
		}
		defer decoded.Close()
		reader = decoded
	default:
		return nil, false
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	return decoded, err == nil && len(decoded) <= 64<<10
}
