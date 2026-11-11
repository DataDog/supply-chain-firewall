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
	"fmt"
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
		for _, format := range []string{"gzip", "zip", "zstd", "zstd-skippable"} {
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
			mediaType := "application/octet-stream"
			if strings.HasPrefix(format, "zstd") {
				mediaType = "application/zstd"
			}
			response := proxy.Response{Request: request, StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": {mediaType}, "Content-Disposition": {`attachment; filename="misleading-9.0.tar.gz"`}}}
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
		{"application/zstd", false, true},
		{"application/x-zstd", false, true},
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
	for _, format := range []string{"zip", "zstd"} {
		payload := packageArchive(t, format, []archiveTestEntry{{name: "project-1.0.dist-info/METADATA", body: readPyPIFixture(t, "archive/PKG-INFO")}})
		for _, encoding := range []string{"gzip", "deflate", "br", "zstd"} {
			t.Run(format+"/"+encoding, func(t *testing.T) {
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
}

func TestOpaqueCachedAndPartialResponses(t *testing.T) {
	payload := packageArchive(t, "gzip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: readPyPIFixture(t, "archive/PKG-INFO")}})
	for _, status := range []int{http.StatusNotModified, http.StatusPartialContent} {
		for _, direct := range []bool{false, true} {
			for _, block := range []bool{false, true} {
				t.Run(fmt.Sprintf("status=%d/direct=%t/block=%t", status, direct, block), func(t *testing.T) {
					fetched := 0
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						fetched++
						if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Range") != "" || r.Header.Get("Range") != "" || r.Header.Get("Authorization") != "Bearer credential-secret" {
							t.Error("full inspection request lost authentication or retained conditional/range headers")
						}
						w.Header().Set("Vary", "Accept, Accept-Encoding")
						if r.Header.Get("Accept") != "application/octet-stream" || r.Header.Get("Accept-Encoding") != "identity" {
							// This endpoint serves HTML unless the caller selects the
							// same package representation as the cached/ranged request.
							w.Header().Set("Content-Type", "text/html")
							return
						}
						w.Header().Set("Content-Type", "application/octet-stream")
						_, _ = w.Write(payload)
					}))
					defer server.Close()
					calls := 0
					handler, request := opaqueHandler(t, server.URL+"/download/abc123", direct, func(_ context.Context, artifact Artifact) error {
						calls++
						if artifact.Name != "project" || artifact.Version != "1.0" {
							t.Errorf("unexpected archive identity: %+v", artifact)
						}
						if block {
							return errors.New("blocked by caller")
						}
						return nil
					})
					handler.Client = server.Client()
					request.Header = http.Header{
						"Accept": {"application/octet-stream"}, "Accept-Encoding": {"identity"},
						"If-None-Match": {`"warm-cache"`}, "If-Range": {`"resume-version"`}, "Range": {"bytes=100-"},
						"Authorization": {"Bearer credential-secret"},
					}
					response := proxy.Response{Request: request, StatusCode: status, Header: http.Header{"Content-Type": {"application/octet-stream"}}}
					hook, err := handler.ObserveResponseHeaders(context.Background(), response)
					if hook != nil || calls != 1 || fetched != 1 || errors.Is(err, proxy.ErrResponseRejected) != block || (err != nil) != block {
						t.Fatalf("hook=%v calls=%d fetches=%d error=%v", hook != nil, calls, fetched, err)
					}
					if request.Header.Get("Range") == "" || request.Header.Get("If-Range") == "" || request.Header.Get("Accept") != "application/octet-stream" || !strings.Contains(request.Header.Get("Authorization"), "credential-secret") {
						t.Fatal("original request headers were mutated")
					}
				})
			}
		}
	}
}

func TestArchiveURLInspectionIgnoresMediaTypeAndFollowsRedirects(t *testing.T) {
	for _, format := range []string{"gzip", "zstd", "zstd-skippable"} {
		payload := packageArchive(t, format, []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: readPyPIFixture(t, "archive/PKG-INFO")}})
		suffix := ".tar.gz"
		if strings.HasPrefix(format, "zstd") {
			suffix = ".tar.zst"
		}
		for _, mediaType := range []string{"text/plain", "text/html", "application/json"} {
			for _, status := range []int{http.StatusOK, http.StatusPartialContent, http.StatusNotModified} {
				t.Run(fmt.Sprintf("%s/%s/%d", format, mediaType, status), func(t *testing.T) {
					handler, request := opaqueHandler(t, "https://packages.example/download"+suffix+"?token=secret", false, func(context.Context, Artifact) error { return proxy.ErrResponseRejected })
					handler.Classifier.inspectArchiveURLs = true
					handler.Classifier.selectArchive = func(input ArchiveInput) (ArchiveFormat, error) {
						if input.CachedHeaders != (status == http.StatusNotModified) {
							t.Errorf("cached header provenance=%v, status=%d", input.CachedHeaders, status)
						}
						if input.URL.Path == input.ResponseURL.Path {
							return ArchiveUnknown, nil
						}
						if !strings.HasSuffix(input.URL.Path, suffix) || input.ResponseURL.Host != "cdn.example" {
							t.Errorf("lost archive provenance: %s -> %s", input.URL.Path, input.ResponseURL.Host)
						}
						if strings.HasPrefix(format, "zstd") {
							return ArchiveZstandard, nil
						}
						return ArchiveGzip, nil
					}
					for _, destination := range []string{"https://cdn.example/redirect", "https://cdn.example/opaque?token=secret"} {
						hook, err := handler.ObserveResponseHeaders(context.Background(), proxy.Response{Request: request, StatusCode: http.StatusFound, Header: http.Header{"Location": {destination}}})
						if err != nil || hook != nil {
							t.Fatalf("redirect: %v/%v", hook, err)
						}
						request.URL = *downloadTestURL(t, destination)
					}
					origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", mediaType)
						_, _ = w.Write(payload)
					}))
					defer origin.Close()
					// Route independent refreshes to the loopback server while keeping
					// the original opaque request and its redirect classification.
					handler.Client = &http.Client{Transport: downloadRoundTripper(func(r *http.Request) (*http.Response, error) {
						clone := r.Clone(r.Context())
						clone.URL = downloadTestURL(t, origin.URL)
						return http.DefaultTransport.RoundTrip(clone)
					})}
					response := proxy.Response{Request: request, StatusCode: status, Header: http.Header{"Content-Type": {mediaType}}}
					hook, err := handler.ObserveResponseHeaders(context.Background(), response)
					if hook != nil {
						err = hook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload))))
					}
					if !errors.Is(err, proxy.ErrResponseRejected) {
						t.Fatalf("archive escaped policy: hook=%v, %v", hook != nil, err)
					}
				})
			}
		}
	}
}

func TestArchiveURLInspectionRetainsMetadata(t *testing.T) {
	for _, encoding := range []string{"", "gzip"} {
		handler, request := opaqueHandler(t, "https://index.example/listing/download.tar.gz", false, func(context.Context, Artifact) error { t.Fatal("metadata reached policy"); return nil })
		handler.Classifier.inspectArchiveURLs = true
		handler.Classifier.selectArchive = func(ArchiveInput) (ArchiveFormat, error) {
			t.Fatal("registry JSON reached archive selection")
			return ArchiveUnknown, nil
		}
		handler.Metadata.RegisterProject(request.URL, "my-project", nil)
		payload := []byte(readPyPIJSONFixture(t, "metadata/artifact-endpoint-simple"))
		if encoding == "gzip" {
			var encoded bytes.Buffer
			writer := gzip.NewWriter(&encoded)
			_, _ = writer.Write(payload)
			_ = writer.Close()
			payload = encoded.Bytes()
		}
		response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/vnd.pypi.simple.v1+json"}, "Content-Encoding": {encoding}}}
		hook, err := handler.ObserveResponseHeaders(context.Background(), response)
		if err != nil || hook == nil || hook.HandleFile == nil {
			t.Fatalf("metadata hook=%v, %v", hook != nil, err)
		}
		if err := hook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload)))); err != nil {
			t.Fatal(err)
		}
		artifact, found := handler.Metadata.ArtifactForURL(downloadTestURL(t, "https://index.example/files/recent?token=one"))
		if !found || artifact.Name != "my-project" || artifact.Version != "1.0" {
			t.Fatalf("metadata observation lost: %+v/%v", artifact, found)
		}
	}
}

func downloadTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

type downloadRoundTripper func(*http.Request) (*http.Response, error)

func (f downloadRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestArchiveRedirectRejectsConflictingInterpretations(t *testing.T) {
	for _, collision := range []bool{false, true} {
		t.Run(fmt.Sprintf("colliding-origins=%v", collision), func(t *testing.T) {
			handler, request := opaqueHandler(t, "https://source.example/start.tar.gz", true, func(context.Context, Artifact) error { t.Fatal("uncertain archive reached policy"); return nil })
			handler.Classifier.inspectArchiveURLs = true
			handler.Classifier.selectArchive = func(input ArchiveInput) (ArchiveFormat, error) {
				if strings.HasSuffix(input.URL.Path, ".zip") {
					return ArchiveZIP, nil
				}
				return ArchiveGzip, nil
			}
			destination := "https://cdn.example/allowed-1.0.zip"
			_, err := handler.ObserveResponseHeaders(context.Background(), proxy.Response{Request: request, StatusCode: http.StatusFound, Header: http.Header{"Location": {destination}}})
			if err != nil {
				t.Fatal(err)
			}
			if collision {
				second := request
				second.URL = *downloadTestURL(t, "https://other.example/different.tar.gz")
				_, err = handler.ObserveResponseHeaders(context.Background(), proxy.Response{Request: second, StatusCode: http.StatusFound, Header: http.Header{"Location": {destination}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			request.URL = *downloadTestURL(t, destination)
			response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/octet-stream"}}}
			headers, err := handler.HandleRequest(context.Background(), request)
			if err != nil || headers == nil {
				t.Fatalf("redirect request hook: %v/%v", headers != nil, err)
			}
			hook, err := headers(context.Background(), response)
			if err != nil || hook == nil {
				t.Fatalf("body hook: %v/%v", hook, err)
			}
			payload := packageArchive(t, "gzip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: readPyPIFixture(t, "archive/PKG-INFO")}})
			err = hook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload))))
			if err == nil || strings.Contains(err.Error(), "source.example") {
				t.Fatalf("conflicting archive origin was not safely rejected: %v", err)
			}
		})
	}
}

func TestArchiveSelectionCannotFallBackOrReleaseUnknownPackage(t *testing.T) {
	payload := packageArchive(t, "zip", []archiveTestEntry{{name: "data.csv", body: "unrelated"}})
	for _, test := range []struct {
		name   string
		format ArchiveFormat
		err    error
	}{
		{name: "unusable selected archive", format: ArchiveZIP},
		{name: "wrong selected format", format: ArchiveGzip},
		{name: "unknown interpretation", format: ArchiveUnknown},
		{name: "selector failed", err: errors.New("archive selection failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, request := opaqueHandler(t, "https://source.example/download.zip", true, func(context.Context, Artifact) error { t.Fatal("unidentified archive reached policy"); return nil })
			handler.Classifier.selectArchive = func(ArchiveInput) (ArchiveFormat, error) { return test.format, test.err }
			response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/octet-stream"}}}
			hook, err := handler.ObserveResponseHeaders(context.Background(), response)
			if err != nil || hook == nil {
				t.Fatalf("body hook: %v/%v", hook, err)
			}
			if err := hook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload)))); err == nil {
				t.Fatal("unidentified package bytes were released")
			}
		})
	}
}

func TestManagerArchiveInspectionKeepsCompressedRequirements(t *testing.T) {
	for _, retain := range []bool{false, true} {
		handler, request := opaqueHandler(t, "https://source.example/requirements.gz", false, func(context.Context, Artifact) error { t.Fatal("requirements reached package policy"); return nil })
		handler.Classifier.retainArchiveContentEncoding = retain
		handler.Classifier.selectArchive = func(ArchiveInput) (ArchiveFormat, error) {
			if retain {
				return ArchiveGzip, nil
			}
			return ArchiveUnknown, nil
		}
		var payload bytes.Buffer
		writer := gzip.NewWriter(&payload)
		if _, err := io.WriteString(writer, "project==1.0\n"); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {"gzip"}}}
		hook, err := handler.ObserveResponseHeaders(context.Background(), response)
		if err != nil || hook == nil {
			t.Fatalf("body hook: %v/%v", hook, err)
		}
		if err := hook.HandleFile(context.Background(), response, io.NewSectionReader(bytes.NewReader(payload.Bytes()), 0, int64(payload.Len()))); err != nil {
			t.Fatalf("compressed requirements were rejected: retain=%v err=%v", retain, err)
		}
	}
}

func TestPartialArchiveSelectionUsesManagerVisibleHeaders(t *testing.T) {
	payload := packageArchive(t, "zip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: readPyPIFixture(t, "archive/PKG-INFO")}})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A refresh must not replace the interpretation visible on the original 206.
		w.Header().Set("Content-Type", "application/x-gzip")
		_, _ = w.Write(payload)
	}))
	defer origin.Close()
	calls := 0
	handler, request := opaqueHandler(t, origin.URL+"/download.zip", true, func(context.Context, Artifact) error { calls++; return proxy.ErrResponseRejected })
	handler.Client = origin.Client()
	handler.Classifier.selectArchive = func(input ArchiveInput) (ArchiveFormat, error) {
		if input.Header.Get("Content-Type") != "application/zip" || input.CachedHeaders {
			t.Error("partial response lost its manager-visible headers")
		}
		return ArchiveZIP, nil
	}
	response := proxy.Response{Request: request, StatusCode: http.StatusPartialContent, Header: http.Header{"Content-Type": {"application/zip"}}}
	hook, err := handler.ObserveResponseHeaders(context.Background(), response)
	if hook != nil || !errors.Is(err, proxy.ErrResponseRejected) || calls != 1 {
		t.Fatalf("partial archive: hook=%v err=%v calls=%d", hook != nil, err, calls)
	}
	if response.Header.Get("Content-Type") != "application/zip" || response.StatusCode != http.StatusPartialContent {
		t.Fatal("mutated forwarded response metadata")
	}
}
