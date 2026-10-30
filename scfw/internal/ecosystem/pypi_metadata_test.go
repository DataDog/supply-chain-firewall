// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestPyPIMetadataCacheObservesJSONAPIAndSimpleAPI(t *testing.T) {
	tests := []struct {
		name        string
		requestURL  string
		contentType string
		body        string
		filename    string
		source      string
		want        time.Time
	}{
		{
			name:        "JSON API exact release file",
			requestURL:  "https://pypi.org/pypi/project/json",
			contentType: "application/json",
			body:        `{"releases":{"1.0":[{"filename":"project-1.0.tar.gz","url":"https://files.pythonhosted.org/project-1.0.tar.gz","upload_time_iso_8601":"2025-01-02T03:04:05Z"}]}}`,
			filename:    "project-1.0.tar.gz",
			source:      "https://files.pythonhosted.org/project-1.0.tar.gz",
			want:        time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		{
			name:        "Simple JSON PEP 700 upload time",
			requestURL:  "https://index.example/simple/project/",
			contentType: "application/vnd.pypi.simple.v1+json",
			body:        `{"files":[{"filename":"project-1.0-py3-none-any.whl","url":"../../files/project-1.0-py3-none-any.whl#sha256=abc","upload-time":"2025-02-03T04:05:06.123Z"}]}`,
			filename:    "project-1.0-py3-none-any.whl",
			source:      "https://index.example/files/project-1.0-py3-none-any.whl#sha256=abc",
			want:        time.Date(2025, 2, 3, 4, 5, 6, 123000000, time.UTC),
		},
		{
			name:        "version JSON API urls",
			requestURL:  "https://pypi.org/pypi/project/1.0/json",
			contentType: "application/json",
			body:        `{"urls":[{"filename":"project-1.0-py2-none-any.whl","url":"https://files.pythonhosted.org/project-1.0-py2-none-any.whl","upload_time_iso_8601":"2025-02-04T05:06:07Z"}]}`,
			filename:    "project-1.0-py2-none-any.whl",
			source:      "https://files.pythonhosted.org/project-1.0-py2-none-any.whl",
			want:        time.Date(2025, 2, 4, 5, 6, 7, 0, time.UTC),
		},
		{
			name:        "Simple HTML optional upload-time extension",
			requestURL:  "https://index.example/simple/project/",
			contentType: "application/vnd.pypi.simple.v1+html; charset=UTF-8",
			body:        `<html><body><a data-requires-python=">=3.9" data-upload-time="2025-03-04T05:06:07Z" href="../../files/project-1.0.zip?token=x#sha256=abc">project</a></body></html>`,
			filename:    "project-1.0.zip",
			source:      "https://index.example/files/project-1.0.zip?token=x#sha256=abc",
			want:        time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestURL, _ := url.Parse(test.requestURL)
			cache := &PyPIMetadataCache{}
			observer := cache.Observe(*requestURL, http.Header{"Content-Type": []string{test.contentType}})
			for _, chunk := range []string{test.body[:len(test.body)/2], test.body[len(test.body)/2:]} {
				if _, err := observer.Write([]byte(chunk)); err != nil {
					t.Fatal(err)
				}
			}
			if err := observer.Close(); err != nil {
				t.Fatal(err)
			}
			artifactURL, _ := url.Parse(test.source)
			artifact, found := cache.ArtifactForURL(artifactURL)
			if !found || artifact.Filename != test.filename {
				t.Fatalf("ArtifactForURL(%q) = %#v, %v", test.source, artifact, found)
			}
			got, found := cache.PublishDate(artifact)
			if !found || !got.Equal(test.want) {
				t.Fatalf("PublishDate(%q) = %v, %v; want %v, true", test.filename, got, found, test.want)
			}
		})
	}
}

func TestPyPIMetadataCacheHTMLBaseURL(t *testing.T) {
	const filename = "project-1.0-py3-none-any.whl"
	for _, test := range []struct {
		name string
		html string
		url  string
	}{
		{
			name: "absolute base",
			html: `<base href="https://cdn.example/files/"><a href="` + filename + `?token=secret">wheel</a>`,
			url:  "https://cdn.example/files/" + filename + "?token=secret",
		},
		{
			name: "relative base",
			html: `<base href="../../files/"><a href="` + filename + `">wheel</a>`,
			url:  "https://index.example/files/" + filename,
		},
		{
			name: "first base applies to earlier anchors",
			html: `<a href="` + filename + `">wheel</a><base href="https://cdn.example/files/"><base href="https://ignored.example/">`,
			url:  "https://cdn.example/files/" + filename,
		},
		{
			name: "base without href does not override later base",
			html: `<base target="_blank"><base href="//cdn.example/files/"><a href="` + filename + `">wheel</a>`,
			url:  "https://cdn.example/files/" + filename,
		},
		{
			name: "empty first href uses document URL",
			html: `<base href=""><base href="https://ignored.example/"><a href="` + filename + `">wheel</a>`,
			url:  "https://index.example/simple/project/" + filename,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, _ := url.Parse("https://index.example/simple/project/")
			cache := &PyPIMetadataCache{}
			observer := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"text/html"}})
			_, _ = io.WriteString(observer, test.html)
			if err := observer.Close(); err != nil {
				t.Fatal(err)
			}
			artifactURL, _ := url.Parse(test.url)
			artifact, found := cache.ArtifactForURL(artifactURL)
			if !found || artifact.Name != "project" || artifact.Version != "1.0" || artifact.Filename != filename {
				t.Fatalf("ArtifactForURL(%q) = %#v, %v; want project@1.0", test.url, artifact, found)
			}
			if artifact.Source != canonicalPyPIURL(nil, test.url) {
				t.Fatalf("source = %q, want redacted base-resolved URL", artifact.Source)
			}
		})
	}
}

func TestPyPIMetadataCacheRecognizesOpaqueWheelCoreMetadata(t *testing.T) {
	endpoint, _ := url.Parse("https://index.example/simple/project/")
	cache := &PyPIMetadataCache{}
	observer := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}})
	_, _ = observer.Write([]byte(`{"files":[{"filename":"project-1.0-py3-none-any.whl","url":"/objects/opaque?id=wheel"}]}`))
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	metadataURL, _ := url.Parse("https://index.example/objects/opaque.metadata?id=wheel")
	if !cache.IsCoreMetadataURL(metadataURL) {
		t.Fatal("advertised opaque .whl.metadata URL was not recognized")
	}
	artifactURL, _ := url.Parse("https://index.example/objects/opaque?id=wheel")
	if cache.IsCoreMetadataURL(artifactURL) {
		t.Fatal("wheel artifact URL was mistaken for core metadata")
	}
}

func TestPyPIMetadataCacheOrdinaryHTMLHasNoUploadTime(t *testing.T) {
	endpoint, _ := url.Parse("https://index.example/simple/project/")
	cache := &PyPIMetadataCache{}
	observer := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+html"}})
	_, _ = observer.Write([]byte(`<a href="/files/project-1.0.tar.gz#sha256=digest">project</a>`))
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	artifactURL, _ := url.Parse("https://index.example/files/project-1.0.tar.gz")
	artifact, found := cache.ArtifactForURL(artifactURL)
	if !found {
		t.Fatal("ordinary Simple HTML did not retain advertised artifact identity")
	}
	if date, found := cache.PublishDate(artifact); found || !date.IsZero() {
		t.Fatalf("PublishDate() = %v, %v; ordinary HTML must use independent JSON fallback", date, found)
	}
}

func TestPyPIMetadataCacheDeduplicatesConcurrentDiscovery(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-release
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}},
			Body:       io.NopCloser(strings.NewReader(`{"files":[]}`)),
			Request:    request,
		}, nil
	})}
	endpoint, _ := url.Parse("https://index.example/python-packages/project/")
	cache := &PyPIMetadataCache{}
	const workers = 8
	errorsSeen := make(chan error, workers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			errorsSeen <- cache.Discover(context.Background(), client, "project", []url.URL{*endpoint}, nil, nil)
		}()
	}
	<-started
	close(release)
	waitGroup.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("metadata discovery requests = %d, want 1", requests.Load())
	}
}

func TestPyPIMetadataCacheDecodesGzipWithoutChangingStreamContract(t *testing.T) {
	body := []byte(`{"files":[{"filename":"project-1.0.tar.gz","url":"../../files/project-1.0.tar.gz","upload-time":"2025-04-05T06:07:08Z"}]}`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(body)
	_ = writer.Close()

	requestURL, _ := url.Parse("https://index.example/simple/project/")
	cache := &PyPIMetadataCache{}
	observer := cache.Observe(*requestURL, http.Header{
		"Content-Type":     []string{"application/vnd.pypi.simple.v1+json"},
		"Content-Encoding": []string{"gzip"},
	})
	if written, err := observer.Write(compressed.Bytes()); err != nil || written != compressed.Len() {
		t.Fatalf("Write() = %d, %v; want %d, nil", written, err, compressed.Len())
	}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	artifactURL, _ := url.Parse("https://index.example/files/project-1.0.tar.gz")
	artifact, found := cache.ArtifactForURL(artifactURL)
	if !found {
		t.Fatal("gzip metadata did not advertise its artifact URL")
	}
	date, found := cache.PublishDate(artifact)
	want := time.Date(2025, 4, 5, 6, 7, 8, 0, time.UTC)
	if !found || !date.Equal(want) {
		t.Fatalf("gzip date = %v, %v; want %v, true", date, found, want)
	}
}

func TestPyPIMetadataCacheKeepsOpaqueSourcesIndependent(t *testing.T) {
	cache := &PyPIMetadataCache{}
	for _, metadata := range []struct {
		endpoint string
		body     string
	}{
		{
			endpoint: "https://user:secret@primary.example/simple/project/",
			body:     `{"files":[{"filename":"project-1.0.tar.gz","url":"../../objects/primary?token=secret#sha256=abc","upload-time":"2025-01-01T01:00:00Z"}]}`,
		},
		{
			endpoint: "https://extra.example/simple/project/",
			body:     `{"files":[{"filename":"project-1.0.tar.gz","url":"../../objects/extra?signature=secret","upload-time":"2025-02-02T02:00:00Z"}]}`,
		},
	} {
		requestURL, _ := url.Parse(metadata.endpoint)
		observer := cache.Observe(*requestURL, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}})
		_, _ = observer.Write([]byte(metadata.body))
		if err := observer.Close(); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		source string
		want   time.Time
	}{
		{source: "https://user:secret@primary.example/objects/primary?token=secret", want: time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)},
		{source: "https://extra.example/objects/extra?signature=secret", want: time.Date(2025, 2, 2, 2, 0, 0, 0, time.UTC)},
	}
	for _, test := range tests {
		requestURL, _ := url.Parse(test.source)
		artifact, found := cache.ArtifactForURL(requestURL)
		if !found || artifact.Name != "project" || artifact.Version != "1.0" || artifact.Filename != "project-1.0.tar.gz" {
			t.Fatalf("ArtifactForURL(%q) = %#v, %v", test.source, artifact, found)
		}
		date, found := cache.PublishDate(artifact)
		if !found || !date.Equal(test.want) {
			t.Fatalf("PublishDate(%q) = %v, %v; want %v, true", test.source, date, found, test.want)
		}
		if strings.Contains(artifact.Source, "secret") || strings.Contains(artifact.Source, "token") || strings.Contains(artifact.Source, "signature") {
			t.Fatalf("canonical source exposes credentials: %q", artifact.Source)
		}
	}
}

func TestPyPIMetadataCacheDistinguishesOpaqueQueryVariants(t *testing.T) {
	endpoint, _ := url.Parse("https://index.example/simple/projects/")
	cache := &PyPIMetadataCache{}
	observer := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}})
	_, _ = observer.Write([]byte(`{"files":[` +
		`{"filename":"alpha-1.0.tar.gz","url":"/download?id=wheel-a&token=first-secret","upload-time":"2025-09-01T01:00:00Z"},` +
		`{"filename":"beta-2.0.tar.gz","url":"/download?id=wheel-b&token=second-secret","upload-time":"2025-09-02T02:00:00Z"}` +
		`]}`))
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		source, name, version string
		want                  time.Time
	}{
		{source: "https://index.example/download?id=wheel-a&token=first-secret", name: "alpha", version: "1.0", want: time.Date(2025, 9, 1, 1, 0, 0, 0, time.UTC)},
		{source: "https://index.example/download?id=wheel-b&token=second-secret", name: "beta", version: "2.0", want: time.Date(2025, 9, 2, 2, 0, 0, 0, time.UTC)},
	}
	var requestKeys []string
	for _, test := range tests {
		requestURL, _ := url.Parse(test.source)
		artifact, found := cache.ArtifactForURL(requestURL)
		if !found || artifact.Name != test.name || artifact.Version != test.version {
			t.Fatalf("ArtifactForURL(%q) = %#v, %v", test.source, artifact, found)
		}
		date, found := cache.PublishDate(artifact)
		if !found || !date.Equal(test.want) {
			t.Fatalf("PublishDate(%q) = %v, %v; want %v, true", test.source, date, found, test.want)
		}
		if artifact.Source != "https://index.example/download" || strings.Contains(artifact.Source, "secret") {
			t.Fatalf("report source = %q, want query-free URL", artifact.Source)
		}
		requestKeys = append(requestKeys, artifact.RequestKey)
	}
	if requestKeys[0] == requestKeys[1] || strings.Contains(requestKeys[0], "first-secret") || strings.Contains(requestKeys[1], "second-secret") {
		t.Fatalf("request keys do not safely distinguish query variants: %q", requestKeys)
	}
}

func TestPyPIMetadataCacheMatchesUniqueUserinfoFreeResource(t *testing.T) {
	endpoint, _ := url.Parse("https://index.example/simple/projects/")
	cache := &PyPIMetadataCache{}
	observer := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}})
	_, _ = observer.Write([]byte(`{"files":[` +
		`{"filename":"project-1.0-py3-none-any.whl","url":"https://user:password@cdn.example/project-1.0-py3-none-any.whl?id=wheel&token=secret","upload-time":"2025-09-03T03:00:00Z"},` +
		`{"filename":"alpha-1.0.tar.gz","url":"https://alpha:secret@cdn.example/shared?id=collision"},` +
		`{"filename":"beta-2.0.tar.gz","url":"https://beta:secret@cdn.example/shared?id=collision"}` +
		`]}`))
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}

	requestURL, _ := url.Parse("https://cdn.example/project-1.0-py3-none-any.whl?id=wheel&token=secret")
	artifact, found := cache.ArtifactForURL(requestURL)
	if !found || artifact.Name != "project" || artifact.Version != "1.0" {
		t.Fatalf("userinfo-free ArtifactForURL() = %#v, %v; want project 1.0", artifact, found)
	}
	if strings.Contains(artifact.Source, "password") || strings.Contains(artifact.Source, "secret") || strings.Contains(artifact.Source, "token") {
		t.Fatalf("report source exposes URL credentials: %q", artifact.Source)
	}
	wrongQuery, _ := url.Parse("https://cdn.example/project-1.0-py3-none-any.whl?id=other&token=secret")
	if _, found := cache.ArtifactForURL(wrongQuery); found {
		t.Fatal("userinfo alias ignored a semantically distinct query")
	}
	ambiguous, _ := url.Parse("https://cdn.example/shared?id=collision")
	if artifact, found := cache.ArtifactForURL(ambiguous); found {
		t.Fatalf("ambiguous credential variants selected the wrong package: %#v", artifact)
	}
}

func TestPyPIMetadataCacheRetainsArtifactIdentityWithoutValidUploadTime(t *testing.T) {
	for _, uploadTime := range []string{"", `,"upload-time":"not-a-time"`} {
		endpoint, _ := url.Parse("https://index.example/simple/project/")
		cache := &PyPIMetadataCache{}
		observer := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}})
		_, _ = observer.Write([]byte(`{"files":[{"filename":"project-1.0.tar.gz","url":"/objects/opaque"` + uploadTime + `}]}`))
		if err := observer.Close(); err != nil {
			t.Fatal(err)
		}
		artifactURL, _ := url.Parse("https://index.example/objects/opaque")
		artifact, found := cache.ArtifactForURL(artifactURL)
		if !found || artifact.Name != "project" || artifact.Version != "1.0" {
			t.Fatalf("ArtifactForURL() = %#v, %v; want project 1.0", artifact, found)
		}
		if date, found := cache.PublishDate(artifact); found || !date.IsZero() {
			t.Fatalf("PublishDate() = %v, %v; want zero, false", date, found)
		}
	}
}

func TestPyPIMetadataCacheIndependentlyRefreshesCustomSimpleEndpoint(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/pypi/repo/simple/project/" {
			http.NotFound(w, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer original" || request.Header.Get("Cookie") != "session=original" {
			http.Error(w, "missing cloned authentication", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_, _ = io.WriteString(w, `{"files":[{"filename":"project-3.0.tar.gz","url":"`+server.URL+`/packages/project-3.0.tar.gz","upload-time":"2025-08-09T10:11:12Z"}]}`)
	}))
	defer server.Close()

	endpoint, _ := url.Parse(server.URL + "/api/pypi/repo/simple/project/")
	cache := &PyPIMetadataCache{}
	header := http.Header{"Authorization": []string{"Bearer original"}, "Cookie": []string{"session=original"}}
	cache.Register(*endpoint, header)
	header.Set("Authorization", "Bearer mutated")
	header.Set("Cookie", "session=mutated")
	artifact := PyPIArtifact{
		Name: "project", Version: "3.0", Filename: "project-3.0.tar.gz", Source: server.URL + "/packages/project-3.0.tar.gz",
	}
	date, err := cache.ResolvePublishDate(context.Background(), server.Client(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 8, 9, 10, 11, 12, 0, time.UTC)
	if !date.Equal(want) {
		t.Fatalf("independent custom-index date = %v, want %v", date, want)
	}
}

func TestPyPIMetadataRefreshErrorRedactsEndpointCredentials(t *testing.T) {
	endpoint, _ := url.Parse("https://user:password@index.example/simple/project/?token=secret")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("request to https://user:password@index.example/?token=secret failed")
	})}
	err := (&PyPIMetadataCache{}).Refresh(context.Background(), client, *endpoint)
	if err == nil {
		t.Fatal("Refresh() returned nil error")
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user") {
		t.Fatalf("Refresh() error exposes credentials: %q", err)
	}
}

func TestPyPIMetadataRefreshRedirectCredentialPolicy(t *testing.T) {
	t.Run("cross origin strips credentials and resolves against final URL", func(t *testing.T) {
		var leaked http.Header
		var finalReferer string
		second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			leaked = request.Header.Clone()
			finalReferer = request.Referer()
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, `{"files":[{"filename":"project-1.0.tar.gz","url":"objects/opaque?id=artifact-secret","upload-time":"2025-10-01T01:02:03Z"}]}`)
		}))
		defer second.Close()
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			http.Redirect(w, request, second.URL+"/redirected/metadata/", http.StatusFound)
		}))
		defer first.Close()

		endpoint, _ := url.Parse(first.URL + "/simple/project/?endpoint_token=query-secret")
		cache := &PyPIMetadataCache{}
		cache.Register(*endpoint, http.Header{
			"Authorization":   []string{"Bearer auth-secret"},
			"Cookie":          []string{"session=cookie-secret"},
			"X-Jfrog-Art-Api": []string{"jfrog-secret"},
			"X-Api-Key":       []string{"api-secret"},
			"X-Private-Token": []string{"private-secret"},
		})
		if err := cache.Refresh(context.Background(), first.Client(), *endpoint); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Jfrog-Art-Api", "X-Api-Key", "X-Private-Token"} {
			if leaked.Get(name) != "" {
				t.Errorf("cross-origin redirect leaked %s=%q", name, leaked.Get(name))
			}
		}
		if finalReferer != "" {
			t.Errorf("cross-origin Referer = %q, want empty", finalReferer)
		}
		artifactURL, _ := url.Parse(second.URL + "/redirected/metadata/objects/opaque?id=artifact-secret")
		artifact, found := cache.ArtifactForURL(artifactURL)
		if !found || artifact.Name != "project" || artifact.Version != "1.0" {
			t.Fatalf("final-origin ArtifactForURL() = %#v, %v", artifact, found)
		}
	})

	t.Run("same origin retains authentication without Referer", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/simple/project/":
				http.Redirect(w, request, "/final/metadata/", http.StatusFound)
			case "/final/metadata/":
				if request.Header.Get("Authorization") != "Bearer auth-secret" || request.Header.Get("Cookie") != "session=cookie-secret" || request.Header.Get("X-Private-Token") != "private-secret" {
					http.Error(w, "missing same-origin authentication", http.StatusUnauthorized)
					return
				}
				if request.Referer() != "" {
					http.Error(w, "credentialed Referer", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				_, _ = io.WriteString(w, `{"files":[{"filename":"project-1.0.tar.gz","url":"`+server.URL+`/objects/opaque","upload-time":"2025-10-02T02:03:04Z"}]}`)
			default:
				http.NotFound(w, request)
			}
		}))
		defer server.Close()
		endpoint, _ := url.Parse(server.URL + "/simple/project/?endpoint_token=query-secret")
		cache := &PyPIMetadataCache{}
		cache.Register(*endpoint, http.Header{
			"Authorization":   []string{"Bearer auth-secret"},
			"Cookie":          []string{"session=cookie-secret"},
			"X-Private-Token": []string{"private-secret"},
		})
		if err := cache.Refresh(context.Background(), server.Client(), *endpoint); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPyPIMetadataCacheBoundsRetainedResponse(t *testing.T) {
	requestURL, _ := url.Parse("https://index.example/simple/project/")
	cache := &PyPIMetadataCache{}
	observer := cache.Observe(*requestURL, http.Header{"Content-Type": []string{"application/json"}})
	data := bytes.Repeat([]byte("x"), maxPyPIMetadataBytes+1)
	if written, err := observer.Write(data); err != nil || written != len(data) {
		t.Fatalf("Write() = %d, %v; want %d, nil", written, err, len(data))
	}
	if err := observer.Close(); err == nil {
		t.Fatal("oversized metadata observer returned nil error")
	}
}

func TestPyPIMetadataCacheBoundsModernCompressedResponse(t *testing.T) {
	decoded := bytes.Repeat([]byte("x"), maxPyPIMetadataBytes+1)
	for _, encoding := range []string{"br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			var encoded bytes.Buffer
			switch encoding {
			case "br":
				writer := brotli.NewWriter(&encoded)
				_, _ = writer.Write(decoded)
				_ = writer.Close()
			case "zstd":
				writer, err := zstd.NewWriter(&encoded)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = writer.Write(decoded)
				_ = writer.Close()
			}
			requestURL, _ := url.Parse("https://index.example/simple/project/")
			observer := (&PyPIMetadataCache{}).Observe(*requestURL, http.Header{
				"Content-Type":     []string{"application/vnd.pypi.simple.v1+json"},
				"Content-Encoding": []string{encoding},
			})
			_, _ = observer.Write(encoded.Bytes())
			if err := observer.Close(); err == nil {
				t.Fatal("oversized decoded metadata returned nil error")
			}
		})
	}
}
