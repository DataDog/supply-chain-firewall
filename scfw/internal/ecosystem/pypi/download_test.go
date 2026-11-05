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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func opaqueHandler(t *testing.T, target string, direct bool, evaluate func(context.Context, Artifact) error) (ProxyHandler, proxy.Request) {
	t.Helper()
	options := RequestClassifierOptions{}
	if direct {
		options.DirectArtifactURLs = []string{target}
	}
	classifier, err := NewRequestClassifier(options)
	if err != nil {
		t.Fatal(err)
	}
	requestURL, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return ProxyHandler{RunContext: context.Background(), Classifier: classifier, Metadata: &MetadataCache{}, EvaluateArtifact: evaluate},
		proxy.Request{Method: http.MethodGet, URL: *requestURL}
}

func TestOpaqueDownloadsEvaluateArchiveIdentity(t *testing.T) {
	metadata := readPyPIFixture(t, "archive/PKG-INFO")
	for _, direct := range []bool{false, true} {
		for _, format := range []string{"gzip", "zip"} {
			calls := 0
			blocked := errors.New("blocked by caller")
			handler, request := opaqueHandler(t, "https://user:credential-secret@packages.example/download/abc123?token=credential-secret", direct,
				func(_ context.Context, artifact Artifact) error {
					calls++
					if artifact.Name != "project" || artifact.Version != "1.0" || artifact.Source != "https://packages.example/download/abc123" || artifact.RequestKey == "" {
						t.Errorf("incorrect or unredacted artifact: %+v", artifact)
					}
					return blocked
				})
			hook, err := handler.HandleRequest(context.Background(), request)
			if err != nil || hook == nil || calls != 0 {
				t.Fatalf("request hook=%v error=%v calls=%d", hook != nil, err, calls)
			}
			response := proxy.Response{Request: request, StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": {"application/octet-stream"}, "Content-Disposition": {`attachment; filename="misleading-9.0.tar.gz"`}}}
			bodyHook, err := hook(context.Background(), response)
			if err != nil || bodyHook == nil || bodyHook.HandleFile == nil {
				t.Fatalf("body hook=%v error=%v", bodyHook != nil, err)
			}
			payload := packageArchive(t, format, []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: metadata}})
			err = bodyHook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload))))
			if !errors.Is(err, blocked) || !errors.Is(err, proxy.ErrResponseRejected) || calls != 1 {
				t.Fatalf("policy calls=%d error=%v", calls, err)
			}
		}
	}
}

func TestOpaqueInspectionKeepsNonPackageTraffic(t *testing.T) {
	for _, test := range []struct {
		mediaType    string
		direct, hook bool
	}{
		{"text/html", false, false},
		{"application/json", false, false},
		{"text/plain", false, false},
		{"application/x-git-upload-pack-result", false, false},
		{"application/octet-stream", false, true},
		{"", false, true},
		{"text/html", true, true},
	} {
		handler, request := opaqueHandler(t, "https://packages.example/download/abc123", test.direct, func(context.Context, Artifact) error {
			t.Fatal("non-package traffic reached policy evaluation")
			return nil
		})
		response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {test.mediaType}}}
		bodyHook, err := handler.ObserveResponseHeaders(context.Background(), response)
		if err != nil || (bodyHook != nil) != test.hook {
			t.Fatalf("%s direct=%v hook=%v error=%v", test.mediaType, test.direct, bodyHook != nil, err)
		}
		if bodyHook != nil {
			payload := []byte("unrelated download")
			err = bodyHook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload))))
			if (err != nil) != test.direct {
				t.Fatalf("%s direct=%v: %v", test.mediaType, test.direct, err)
			}
		}
	}
}

func TestOpaqueArchiveHTTPEncodings(t *testing.T) {
	payload := packageArchive(t, "zip", []archiveTestEntry{{name: "project-1.0.dist-info/METADATA", body: readPyPIFixture(t, "archive/PKG-INFO")}})
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			var encoded bytes.Buffer
			var writer io.WriteCloser
			switch encoding {
			case "gzip":
				writer = gzip.NewWriter(&encoded)
			case "deflate":
				writer = zlib.NewWriter(&encoded)
			case "br":
				writer = brotli.NewWriter(&encoded)
			case "zstd":
				var err error
				writer, err = zstd.NewWriter(&encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			called := false
			err := inspectDecodedArchive(context.Background(), io.NewSectionReader(bytes.NewReader(encoded.Bytes()), 0, int64(encoded.Len())), encoding, func(body *io.SectionReader) error {
				artifact, found, err := inspectArchive(context.Background(), body)
				called = found && artifact.Name == "project" && artifact.Version == "1.0"
				return err
			})
			if err != nil || !called {
				t.Fatalf("identity found=%v error=%v", called, err)
			}
		})
	}
}

func TestOpaqueCachedAndPartialResponses(t *testing.T) {
	payload := packageArchive(t, "gzip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: readPyPIFixture(t, "archive/PKG-INFO")}})
	for _, status := range []int{http.StatusNotModified, http.StatusPartialContent} {
		for _, block := range []bool{false, true} {
			fetched := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fetched++
				if r.Header.Get("If-None-Match") != "" || r.Header.Get("Range") != "" || r.Header.Get("Authorization") != "Bearer credential-secret" {
					t.Error("full inspection request lost authentication or retained conditional/range headers")
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(payload)
			}))
			calls := 0
			handler, request := opaqueHandler(t, server.URL+"/download/abc123", true, func(context.Context, Artifact) error {
				calls++
				if block {
					return errors.New("blocked by caller")
				}
				return nil
			})
			handler.Client = server.Client()
			request.Header = http.Header{"If-None-Match": {`"warm-cache"`}, "Range": {"bytes=100-"}, "Authorization": {"Bearer credential-secret"}}
			response := proxy.Response{Request: request, StatusCode: status, Header: http.Header{"Content-Type": {"application/octet-stream"}}}
			hook, err := handler.ObserveResponseHeaders(context.Background(), response)
			server.Close()
			if hook != nil || calls != 1 || fetched != 1 || errors.Is(err, proxy.ErrResponseRejected) != block || (err != nil) != block {
				t.Fatalf("status=%d block=%v hook=%v calls=%d fetches=%d error=%v", status, block, hook != nil, calls, fetched, err)
			}
			if request.Header.Get("Range") == "" || !strings.Contains(request.Header.Get("Authorization"), "credential-secret") {
				t.Fatal("original request headers were mutated")
			}
		}
	}
}
