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
	"os"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestMetadataBodyEncodingAndSecrets(t *testing.T) {
	fixture, err := os.ReadFile("testdata/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]json.RawMessage
	if err := json.Unmarshal(fixture, &cases); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"identity", "gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			var encoded bytes.Buffer
			var writer io.WriteCloser
			switch encoding {
			case "identity":
				writer = nopWriteCloser{&encoded}
			case "gzip":
				writer = gzip.NewWriter(&encoded)
			case "deflate":
				writer = zlib.NewWriter(&encoded)
			case "br":
				writer = brotli.NewWriter(&encoded)
			case "zstd":
				writer, err = zstd.NewWriter(&encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writer.Write(cases["metadata"]); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			result := MetadataBody(http.Header{"Content-Encoding": []string{encoding}}, encoded.Bytes(), true, func(body []byte) bool { return json.Valid(body) }, NewRedactor(nil, nil))
			text, ok := result["text"].(string)
			if !ok || !strings.Contains(text, "example-package") {
				t.Fatalf("metadata omitted: %v", result)
			}
			for _, secret := range []string{"body-token-canary", "body-userinfo-canary", "body-query-canary"} {
				if strings.Contains(text, secret) {
					t.Errorf("leaked %s", secret)
				}
			}
		})
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestMetadataBodyOmissionsAndTruncation(t *testing.T) {
	r := NewRedactor(nil, nil)
	for _, complete := range []bool{false, true} {
		result := MetadataBody(nil, []byte("PACKAGE-CONTENTS-CANARY"), complete, func([]byte) bool { return false }, r)
		if result["text"] != nil || result["omitted"] == nil {
			t.Fatal("persisted non-metadata body")
		}
	}
	body, _ := json.Marshal(map[string]string{"description": strings.Repeat("harmless ", 2000)})
	result := MetadataBody(nil, body, true, func([]byte) bool { return true }, r)
	if result["truncated"] != true || len(result["text"].(string)) > MaxText {
		t.Fatalf("sample bound: %v", result)
	}
}

func TestMetadataBodySanitizesHTMLBeforeTruncation(t *testing.T) {
	body, err := os.ReadFile("testdata/simple.html")
	if err != nil {
		t.Fatal(err)
	}
	result := MetadataBody(nil, body, true, func([]byte) bool { return true }, NewRedactor(nil, nil))
	text, ok := result["text"].(string)
	if !ok || !strings.Contains(text, "pkg.whl") {
		t.Fatalf("metadata omitted: %v", result)
	}
	for _, secret := range []string{"html-query-canary", "fragment-secret", "html-attribute-canary", "html-text-canary", "comment-secret-canary"} {
		if strings.Contains(text, secret) {
			t.Errorf("leaked %s", secret)
		}
	}
}
