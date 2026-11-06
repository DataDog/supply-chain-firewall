// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

func TestPyPIMetadataCacheRegistersExactRedirectedProject(t *testing.T) {
	source, _ := url.Parse("https://index.example/simple/my_project/")
	cache := &MetadataCache{}
	cache.Register(*source, http.Header{"Authorization": []string{"Bearer source-secret"}})
	cache.RegisterRedirect(*source, "../../catalog/opaque/?token=one#fragment")
	first, _ := url.Parse("https://index.example/catalog/opaque/?token=one")
	cache.RegisterRedirect(*first, "https://redirect-user:redirect-password@cdn.example/listing?token=two")
	final, _ := url.Parse("https://cdn.example/listing?token=two")
	cache.RegisterRedirect(*final, "https://root.example?token=three")
	root, _ := url.Parse("https://root.example/?token=three")
	for _, endpoint := range []*url.URL{first, final, root} {
		if project, _, found := cache.ProjectForURL(endpoint); !found || project != "my-project" {
			t.Fatalf("ProjectForURL(%s) = %q, %t; want my-project, true", endpoint, project, found)
		}
		if header := cache.endpoints[pyPIURLRequestKey(nil, endpoint.String())].header; len(header) != 0 {
			t.Fatalf("redirect destination inherited source headers: %v", header)
		}
	}
	for _, rawURL := range []string{
		"https://index.example/catalog/opaque/?token=other",
		"https://cdn.example/listing?token=other",
		"https://cdn.example/unrelated?token=two",
		"https://root.example/?token=other",
	} {
		endpoint, _ := url.Parse(rawURL)
		if _, _, found := cache.ProjectForURL(endpoint); found {
			t.Fatalf("unregistered URL %s inherited Simple API context", endpoint)
		}
	}
	if _, _, found := cache.ProjectForURL(nil); found {
		t.Fatal("nil URL matched a registered project")
	}
}

func TestPyPIMetadataCacheRejectsInvalidRedirects(t *testing.T) {
	for _, location := range []string{"", "http://[invalid", "file:///tmp/project", "javascript:alert(1)", "mailto:project@example.com"} {
		t.Run(location, func(t *testing.T) {
			source, _ := url.Parse("https://index.example/simple/project/")
			cache := &MetadataCache{}
			cache.Register(*source, nil)
			cache.RegisterRedirect(*source, location)
			if len(cache.endpoints) != 1 {
				t.Fatalf("invalid redirect registered %d endpoints, want only the source", len(cache.endpoints))
			}
		})
	}
	source, _ := url.Parse("https://index.example/unrelated/")
	cache := &MetadataCache{}
	cache.RegisterRedirect(*source, "https://cdn.example/listing/")
	if len(cache.endpoints) != 0 {
		t.Fatal("unregistered redirect source established Simple API context")
	}
}

func TestPyPIMetadataCacheObservesJSONAPIAndSimpleAPI(t *testing.T) {
	releaseSdistFixture := readPyPIJSONFixture(t, "metadata/release-sdist")
	simpleWheelDateFixture := readPyPIJSONFixture(t, "metadata/simple-wheel-date")
	versionWheelFixture := readPyPIJSONFixture(t, "metadata/version-wheel")
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
			body:        releaseSdistFixture,
			filename:    "project-1.0.tar.gz",
			source:      "https://files.pythonhosted.org/project-1.0.tar.gz",
			want:        time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		{
			name:        "Simple JSON PEP 700 upload time",
			requestURL:  "https://index.example/simple/project/",
			contentType: "application/vnd.pypi.simple.v1+json",
			body:        simpleWheelDateFixture,
			filename:    "project-1.0-py3-none-any.whl",
			source:      "https://index.example/files/project-1.0-py3-none-any.whl#sha256=abc",
			want:        time.Date(2025, 2, 3, 4, 5, 6, 123000000, time.UTC),
		},
		{
			name:        "version JSON API urls",
			requestURL:  "https://pypi.org/pypi/project/1.0/json",
			contentType: "application/json",
			body:        versionWheelFixture,
			filename:    "project-1.0-py2-none-any.whl",
			source:      "https://files.pythonhosted.org/project-1.0-py2-none-any.whl",
			want:        time.Date(2025, 2, 4, 5, 6, 7, 0, time.UTC),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestURL, _ := url.Parse(test.requestURL)
			cache := &MetadataCache{}

			if err := cache.Observe(*requestURL, http.Header{"Content-Type": []string{test.contentType}}, []byte(test.body)); err != nil {
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

func TestPyPIMetadataCacheUsesProjectContextForLegacySdists(t *testing.T) {
	legacySdistFixture := readPyPIJSONFixture(t, "metadata/legacy-sdist")
	legacySdistNameFixture := readPyPIJSONFixture(t, "metadata/legacy-sdist-name")
	legacyReleaseFixture := readPyPIJSONFixture(t, "metadata/legacy-release")
	legacyVersionInfoFixture := readPyPIJSONFixture(t, "metadata/legacy-version-info")
	for _, test := range []struct {
		name, endpoint, contentType, body, registered string
	}{
		{"redirected JSON", "https://index.example/opaque", "application/json", legacySdistFixture, "project"},
		{"redirected project path", "https://index.example/simple/other/", "application/json", legacySdistFixture, "project"},
		{"simple JSON", "https://index.example/simple/project/", "application/vnd.pypi.simple.v1+json", legacySdistFixture, ""},
		{"JSON project name", "https://index.example/opaque", "application/json", legacySdistNameFixture, ""},
		{"JSON API", "https://pypi.org/pypi/project/json", "application/json", legacyReleaseFixture, ""},
		{"JSON info name", "https://index.example/opaque", "application/json", legacyVersionInfoFixture, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := &MetadataCache{}
			endpoint, _ := url.Parse(test.endpoint)
			if test.registered != "" {
				original, _ := url.Parse("https://index.example/simple/" + test.registered + "/")
				cache.Register(*original, nil)
				cache.RegisterRedirect(*original, test.endpoint)
			}
			if err := cache.Observe(*endpoint, http.Header{"Content-Type": {test.contentType}}, []byte(test.body)); err != nil {
				t.Fatal(err)
			}
			artifactURL, _ := url.Parse("https://cdn.example/project-1.0-1.tar.gz")
			artifact, found := cache.ArtifactForURL(artifactURL)
			if !found || artifact.Name != "project" || artifact.Version != "1.0.post1" {
				t.Fatalf("advertised identity = %#v, %t; want project 1.0.post1", artifact, found)
			}
			if test.registered != "" {
				if project, _, found := cache.ProjectForURL(endpoint); !found || project != test.registered {
					t.Fatalf("observation replaced redirected project context with %q", project)
				}
			}
		})
	}
}

func TestPyPIMetadataCacheRefreshRetainsProjectAcrossRedirect(t *testing.T) {
	legacySdistFixture := readPyPIJSONFixture(t, "metadata/legacy-sdist")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/simple/project/" {
			http.Redirect(w, request, "/opaque", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_, _ = io.WriteString(w, legacySdistFixture)
	}))
	defer server.Close()
	cache := &MetadataCache{}
	endpoint, _ := url.Parse(server.URL + "/simple/project/")
	cache.Register(*endpoint, nil)
	if err := cache.Refresh(context.Background(), server.Client(), *endpoint); err != nil {
		t.Fatal(err)
	}
	artifactURL, _ := url.Parse("https://cdn.example/project-1.0-1.tar.gz")
	artifact, found := cache.ArtifactForURL(artifactURL)
	if !found || artifact.Name != "project" || artifact.Version != "1.0.post1" {
		t.Fatalf("refreshed identity = %#v, %t; want project 1.0.post1", artifact, found)
	}
}

func TestPyPIMetadataCacheRejectsFilesForAnotherProject(t *testing.T) {
	otherProjectFixture := readPyPIFixture(t, "metadata/other-project.json.tmpl")
	for _, filename := range []string{"other-1.0.tar.gz", "other-1.0-py3-none-any.whl"} {
		cache := &MetadataCache{}
		endpoint, _ := url.Parse("https://index.example/simple/project/")
		body := fmt.Sprintf(otherProjectFixture, filename)
		if err := cache.Observe(*endpoint, http.Header{"Content-Type": {"application/json"}}, []byte(body)); err != nil {
			t.Fatal(err)
		}
		artifactURL, _ := url.Parse("https://cdn.example/opaque")
		if artifact, found := cache.ArtifactForURL(artifactURL); found {
			t.Fatalf("accepted another project's artifact: %#v", artifact)
		}
	}
}

func TestPyPIMetadataCacheIgnoresHTML(t *testing.T) {
	baseUploadTimeFixture := readPyPIFixture(t, "metadata/base-upload-time.html")
	for _, contentType := range []string{"text/html", "application/vnd.pypi.simple.v1+html", "application/xhtml+xml"} {
		endpoint, _ := url.Parse("https://index.example/simple/project/")
		cache := &MetadataCache{}
		header := http.Header{"Content-Type": {contentType}, "Content-Encoding": {"gzip"}}
		// Deliberately invalid compressed bytes must not be decoded or parsed as HTML.
		body := []byte(baseUploadTimeFixture)
		if err := cache.Observe(*endpoint, header, body); err != nil {
			t.Fatal(err)
		}
		artifactURL, _ := url.Parse("https://cdn.example/project-1.0.tar.gz")
		if _, found := cache.ArtifactForURL(artifactURL); found || cache.HasObserved(*endpoint) {
			t.Fatal("HTML populated JSON metadata state")
		}
	}
}

func TestPyPIMetadataCacheRecognizesOpaqueWheelCoreMetadata(t *testing.T) {
	opaqueWheelFixture := readPyPIJSONFixture(t, "metadata/opaque-wheel")
	endpoint, _ := url.Parse("https://index.example/simple/project/")
	cache := &MetadataCache{}

	if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(opaqueWheelFixture)); err != nil {
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

func TestPyPIMetadataCacheDeduplicatesConcurrentDiscovery(t *testing.T) {
	emptySimpleFixture := readPyPIJSONFixture(t, "metadata/empty-simple")
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
			Body:       io.NopCloser(strings.NewReader(emptySimpleFixture)),
			Request:    request,
		}, nil
	})}
	endpoint, _ := url.Parse("https://index.example/python-packages/project/")
	cache := &MetadataCache{}
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

func TestPyPIMetadataCacheDecodesGzip(t *testing.T) {
	simpleSdistDateFixture := readPyPIJSONFixture(t, "metadata/simple-sdist-date")
	body := []byte(simpleSdistDateFixture)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(body)
	_ = writer.Close()

	requestURL, _ := url.Parse("https://index.example/simple/project/")
	cache := &MetadataCache{}

	if err := cache.Observe(*requestURL, http.Header{
		"Content-Type":     []string{"application/vnd.pypi.simple.v1+json"},
		"Content-Encoding": []string{"gzip"},
	}, compressed.Bytes()); err != nil {
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
	primarySourceFixture := readPyPIJSONFixture(t, "metadata/primary-source")
	extraSourceFixture := readPyPIJSONFixture(t, "metadata/extra-source")
	cache := &MetadataCache{}
	for _, metadata := range []struct {
		endpoint string
		body     string
	}{
		{
			endpoint: "https://user:secret@primary.example/simple/project/",
			body:     primarySourceFixture,
		},
		{
			endpoint: "https://extra.example/simple/project/",
			body:     extraSourceFixture,
		},
	} {
		requestURL, _ := url.Parse(metadata.endpoint)

		if err := cache.Observe(*requestURL, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(metadata.body)); err != nil {
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
	queryAlphaFixture := readPyPIJSONFixture(t, "metadata/query-alpha")
	queryBetaFixture := readPyPIJSONFixture(t, "metadata/query-beta")
	cache := &MetadataCache{}
	for _, input := range []struct{ project, body string }{
		{"alpha", queryAlphaFixture},
		{"beta", queryBetaFixture},
	} {
		endpoint, _ := url.Parse("https://index.example/simple/" + input.project + "/")
		if err := cache.Observe(*endpoint, http.Header{"Content-Type": {"application/vnd.pypi.simple.v1+json"}}, []byte(input.body)); err != nil {
			t.Fatal(err)
		}
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

func TestPyPIMetadataCacheMatchesEquivalentURLEncodings(t *testing.T) {
	endpoint, _ := url.Parse("https://index.example/simple/project/")
	cache := &MetadataCache{}
	cache.store(endpoint, "project-1.0.tar.gz", "/objects/%61%62%63%2f%7e?token=%6fne%2ftwo&literal=%252F", "2025-01-02T03:04:05Z", "project")
	for _, reference := range []string{
		"/objects/abc%2F~?token=one%2Ftwo&literal=%252F",
		"/objects/%61bc%2f%7E?token=o%6Ee%2ftwo&literal=%252F",
	} {
		requestURL, _ := endpoint.Parse(reference)
		artifact, found := cache.ArtifactForURL(requestURL)
		if !found || artifact.Name != "project" || artifact.Version != "1.0" {
			t.Fatalf("ArtifactForURL(%q) = %#v, %t; want project 1.0", reference, artifact, found)
		}
		if date, found := cache.PublishDate(artifact); !found || date.Format(time.RFC3339) != "2025-01-02T03:04:05Z" {
			t.Fatalf("PublishDate(%q) = %v, %t; want advertised date", reference, date, found)
		}
	}
	for _, reference := range []string{
		"/objects/abc/~?token=one%2Ftwo&literal=%252F",
		"/objects/abc%2F~?token=one/two&literal=%252F",
		"/objects/abc%2F~?token=one%2Ftwo&literal=%2F",
		"/objects/abc%2F~?token=other&literal=%252F",
		"/objects/abc%2F~?literal=%252F&token=one%2Ftwo",
	} {
		requestURL, _ := endpoint.Parse(reference)
		if artifact, found := cache.ArtifactForURL(requestURL); found {
			t.Fatalf("distinct URL %q inherited advertisement: %#v", reference, artifact)
		}
	}
}

func TestPyPIMetadataCacheMatchesUniqueUserinfoFreeResource(t *testing.T) {
	userinfoWheelFixture := readPyPIJSONFixture(t, "metadata/userinfo-wheel")
	userinfoAlphaFixture := readPyPIJSONFixture(t, "metadata/userinfo-alpha")
	userinfoBetaFixture := readPyPIJSONFixture(t, "metadata/userinfo-beta")
	cache := &MetadataCache{}
	for _, input := range []struct{ project, body string }{
		{"project", userinfoWheelFixture},
		{"alpha", userinfoAlphaFixture},
		{"beta", userinfoBetaFixture},
	} {
		endpoint, _ := url.Parse("https://index.example/simple/" + input.project + "/")
		if err := cache.Observe(*endpoint, http.Header{"Content-Type": {"application/vnd.pypi.simple.v1+json"}}, []byte(input.body)); err != nil {
			t.Fatal(err)
		}
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
	opaqueSdistFixture := readPyPIJSONFixture(t, "metadata/opaque-sdist")
	invalidUploadTimeFixture := readPyPIJSONFixture(t, "metadata/invalid-upload-time")
	for _, body := range []string{opaqueSdistFixture, invalidUploadTimeFixture} {
		endpoint, _ := url.Parse("https://index.example/simple/project/")
		cache := &MetadataCache{}

		if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(body)); err != nil {
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

func TestPyPIMetadataCachePreservesKnownUploadTime(t *testing.T) {
	sdistSourceDateFixture := readPyPIFixture(t, "metadata/sdist-source-date.json.tmpl")
	projectFixture := readPyPIFixture(t, "metadata/project.html.tmpl")
	invalidUploadTimeFixture := readPyPIFixture(t, "metadata/invalid-upload-time.html.tmpl")
	for _, credentialed := range []bool{false, true} {
		t.Run(fmt.Sprintf("credentialed=%t", credentialed), func(t *testing.T) {
			cache := &MetadataCache{}
			endpoint, _ := url.Parse("https://index.example/simple/project/")
			source := "https://cdn.example/project-1.0.tar.gz?token=one"
			if credentialed {
				source = "https://user:password@cdn.example/project-1.0.tar.gz?token=one"
			}
			observe := func(contentType, body string) {
				t.Helper()

				if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{contentType}}, []byte(body)); err != nil {
					t.Fatal(err)
				}
			}
			date := time.Date(2025, 5, 6, 7, 8, 9, 123, time.UTC)
			observe("application/vnd.pypi.simple.v1+json", fmt.Sprintf(sdistSourceDateFixture, source, date.Format(time.RFC3339Nano)))
			wireURL, _ := url.Parse("https://cdn.example/project-1.0.tar.gz?token=one")
			for _, body := range []string{
				fmt.Sprintf(projectFixture, source),
				fmt.Sprintf(invalidUploadTimeFixture, source),
			} {
				observe("text/html", body)
				artifact, found := cache.ArtifactForURL(wireURL)
				if !found {
					t.Fatal("same-identity HTML lost the artifact")
				}
				if got, found := cache.PublishDate(artifact); !found || !got.Equal(date) {
					t.Fatalf("known upload time = %v, %t; want %v, true", got, found, date)
				}
			}
			newDate := date.Add(time.Hour)
			observe("application/vnd.pypi.simple.v1+json", fmt.Sprintf(sdistSourceDateFixture, source, newDate.Format(time.RFC3339Nano)))
			artifact, _ := cache.ArtifactForURL(wireURL)
			if got, found := cache.PublishDate(artifact); !found || !got.Equal(newDate) {
				t.Fatalf("refreshed upload time = %v, %t; want %v, true", got, found, newDate)
			}
		})
	}
}

func TestPyPIMetadataCacheRejectsConflictingExactIdentities(t *testing.T) {
	artifactFixedDateFixture := readPyPIFixture(t, "metadata/artifact-fixed-date.json.tmpl")
	for _, conflict := range []string{"beta-1.0.tar.gz", "alpha-2.0.tar.gz", "alpha-1.0-py3-none-any.whl"} {
		t.Run(conflict, func(t *testing.T) {
			cache := &MetadataCache{}
			artifactURL, _ := url.Parse("https://cdn.example/download?token=one")
			observe := func(index, filename string) {
				t.Helper()
				project, _, _ := ParseDistributionFilename(filename)
				endpoint, _ := url.Parse(index + "/simple/" + project + "/")

				if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(fmt.Sprintf(artifactFixedDateFixture, filename, artifactURL.String()))); err != nil {
					t.Fatal(err)
				}
			}
			observe("https://first.example", "alpha-1.0.tar.gz")
			original, found := cache.ArtifactForURL(artifactURL)
			if !found {
				t.Fatal("initial advertisement was not cached")
			}
			observe("https://second.example", conflict)
			for range 2 {
				if artifact, found := cache.ArtifactForURL(artifactURL); found {
					t.Fatalf("conflicting URL selected %#v", artifact)
				}
				if date, found := cache.PublishDate(original); found || !date.IsZero() {
					t.Fatalf("conflicting URL retained usable publication evidence: %v, %t", date, found)
				}
				observe("https://first.example", "alpha-1.0.tar.gz")
			}
		})
	}
}

func TestPyPIMetadataCacheRejectsExactAliasIdentityConflicts(t *testing.T) {
	conflictingAlphaFixture := readPyPIJSONFixture(t, "metadata/conflicting-alpha")
	conflictingBetaFixture := readPyPIJSONFixture(t, "metadata/conflicting-beta")
	for _, aliasFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("aliasFirst=%t", aliasFirst), func(t *testing.T) {
			cache := &MetadataCache{}
			endpoint, _ := url.Parse("https://index.example/catalog/")
			bodies := []string{
				conflictingAlphaFixture,
				conflictingBetaFixture,
			}
			if aliasFirst {
				bodies[0], bodies[1] = bodies[1], bodies[0]
			}
			for _, body := range bodies {

				if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(body)); err != nil {
					t.Fatal(err)
				}
			}
			wireURL, _ := url.Parse("https://cdn.example/shared?token=one")
			if artifact, found := cache.ArtifactForURL(wireURL); found {
				t.Fatalf("exact record and alias selected conflicting identity: %#v", artifact)
			}
		})
	}
}

func TestPyPIMetadataCacheRefreshesMatchingExactAndAliasDates(t *testing.T) {
	sdistSourceDateFixture := readPyPIFixture(t, "metadata/sdist-source-date.json.tmpl")
	cache := &MetadataCache{}
	endpoint, _ := url.Parse("https://index.example/simple/project/")
	wireURL, _ := url.Parse("https://cdn.example/project-1.0.tar.gz?token=one")
	date := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	for _, input := range []struct {
		credentialed bool
		uploadTime   string
		want         time.Time
	}{
		{uploadTime: date.Format(time.RFC3339Nano), want: date},
		{credentialed: true, uploadTime: date.Add(time.Hour).Format(time.RFC3339Nano), want: date.Add(time.Hour)},
		{want: date.Add(time.Hour)},
		{uploadTime: date.Add(2 * time.Hour).Format(time.RFC3339Nano), want: date.Add(2 * time.Hour)},
		{credentialed: true, want: date.Add(2 * time.Hour)},
	} {
		source := *wireURL
		if input.credentialed {
			source.User = url.UserPassword("user", "password")
		}

		if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(fmt.Sprintf(sdistSourceDateFixture, source.String(), input.uploadTime))); err != nil {
			t.Fatal(err)
		}
		artifact, found := cache.ArtifactForURL(wireURL)
		if !found {
			t.Fatal("matching exact and alias records became ambiguous")
		}
		if got, found := cache.PublishDate(artifact); !found || !got.Equal(input.want) {
			t.Fatalf("publication time = %v, %t; want %v, true", got, found, input.want)
		}
	}
}

func TestPyPIMetadataCacheExactConflictAlsoInvalidatesAlias(t *testing.T) {
	artifactFixture := readPyPIFixture(t, "metadata/artifact.json.tmpl")
	cache := &MetadataCache{}
	endpoint, _ := url.Parse("https://index.example/simple/project/")
	credentialed, _ := url.Parse("https://user:password@cdn.example/shared?token=one")
	wireURL, _ := url.Parse("https://cdn.example/shared?token=one")
	for _, input := range []struct{ filename, source string }{
		{"alpha-1.0.tar.gz", credentialed.String()},
		{"beta-2.0.tar.gz", credentialed.String()},
		{"alpha-1.0.tar.gz", wireURL.String()},
	} {

		if err := cache.Observe(*endpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(fmt.Sprintf(artifactFixture, input.filename, input.source))); err != nil {
			t.Fatal(err)
		}
	}
	for _, requestURL := range []*url.URL{credentialed, wireURL} {
		if artifact, found := cache.ArtifactForURL(requestURL); found {
			t.Fatalf("conflicting credentialed URL or its alias selected %#v", artifact)
		}
	}
}

func TestPyPIMetadataCacheIndependentlyRefreshesCustomSimpleEndpoint(t *testing.T) {
	customEndpointFixture := readPyPIFixture(t, "metadata/custom-endpoint.json.tmpl")
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
		_, _ = io.WriteString(w, fmt.Sprintf(customEndpointFixture, server.URL))
	}))
	defer server.Close()

	endpoint, _ := url.Parse(server.URL + "/api/pypi/repo/simple/project/")
	cache := &MetadataCache{}
	header := http.Header{"Authorization": []string{"Bearer original"}, "Cookie": []string{"session=original"}}
	cache.Register(*endpoint, header)
	header.Set("Authorization", "Bearer mutated")
	header.Set("Cookie", "session=mutated")
	artifact := Artifact{
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
	err := (&MetadataCache{}).Refresh(context.Background(), client, *endpoint)
	if err == nil {
		t.Fatal("Refresh() returned nil error")
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user") {
		t.Fatalf("Refresh() error exposes credentials: %q", err)
	}
}

func TestPyPIMetadataRefreshRedirectCredentialPolicy(t *testing.T) {
	redirectCrossOriginFixture := readPyPIJSONFixture(t, "metadata/redirect-cross-origin")
	redirectSameOriginFixture := readPyPIFixture(t, "metadata/redirect-same-origin.json.tmpl")
	t.Run("cross origin strips credentials and resolves against final URL", func(t *testing.T) {
		var leaked http.Header
		var finalReferer string
		second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			leaked = request.Header.Clone()
			finalReferer = request.Referer()
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, redirectCrossOriginFixture)
		}))
		defer second.Close()
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			http.Redirect(w, request, second.URL+"/redirected/metadata/", http.StatusFound)
		}))
		defer first.Close()

		endpoint, _ := url.Parse(first.URL + "/simple/project/?endpoint_token=query-secret")
		cache := &MetadataCache{}
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
				_, _ = io.WriteString(w, fmt.Sprintf(redirectSameOriginFixture, server.URL))
			default:
				http.NotFound(w, request)
			}
		}))
		defer server.Close()
		endpoint, _ := url.Parse(server.URL + "/simple/project/?endpoint_token=query-secret")
		cache := &MetadataCache{}
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
	cache := &MetadataCache{}

	data := bytes.Repeat([]byte("x"), MaxMetadataBytes+1)

	if err := cache.Observe(*requestURL, http.Header{"Content-Type": []string{"application/json"}}, data); err == nil {
		t.Fatal("oversized metadata observer returned nil error")
	}
}

func TestPyPIMetadataCacheBoundsModernCompressedResponse(t *testing.T) {
	decoded := bytes.Repeat([]byte("x"), MaxMetadataBytes+1)
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

			if err := (&MetadataCache{}).Observe(*requestURL, http.Header{
				"Content-Type":     []string{"application/vnd.pypi.simple.v1+json"},
				"Content-Encoding": []string{encoding},
			}, encoded.Bytes()); err == nil {
				t.Fatal("oversized decoded metadata returned nil error")
			}
		})
	}
}

func TestPyPIMetadataSizeLimitDiagnostics(t *testing.T) {
	oversized := bytes.Repeat([]byte("x"), MaxMetadataBytes+1)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(oversized)
	_ = writer.Close()
	for _, mode := range []string{"observation", "decoded observation", "discovery"} {
		t.Run(mode, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)
			endpoint, _ := url.Parse("https://user:password@index.example/simple/project/?token=secret#private")
			cache := &MetadataCache{}
			var err error
			switch mode {
			case "observation":
				err = cache.Observe(*endpoint, nil, oversized)
			case "decoded observation":
				err = cache.Observe(*endpoint, http.Header{"Content-Encoding": {"gzip"}}, compressed.Bytes())
			case "discovery":
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(oversized))}, nil
				})}
				err = cache.Discover(context.Background(), client, "project", []url.URL{*endpoint}, endpoint, nil)
			}
			if !errors.Is(err, errPyPIMetadataTooLarge) {
				t.Fatalf("error = %v; want size limit error", err)
			}
			message := logs.String()
			if !strings.Contains(message, "PyPI metadata exceeds size limit") || !strings.Contains(message, "limit_bytes=8388608") ||
				!strings.Contains(message, "https://index.example/simple/project/") {
				t.Fatalf("missing size-limit diagnostic: %s", message)
			}
			for _, secret := range []string{"user:", "password", "token", "secret", "private", "xxxxxxxx"} {
				if strings.Contains(message, secret) {
					t.Fatalf("size-limit diagnostic exposed %q", secret)
				}
			}
		})
	}
}

func TestPyPIMetadataCacheUsesJSONIdentityAtArtifactEndpoints(t *testing.T) {
	for _, test := range []struct {
		fixture     string
		established bool
	}{
		{"metadata/artifact-endpoint-simple", false},
		{"metadata/artifact-endpoint-release", false},
		{"metadata/artifact-endpoint-version", false},
		{"metadata/artifact-endpoint-filenames", false},
		{"metadata/artifact-endpoint-conflicting-name", true},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			endpoint, _ := url.Parse("https://index.example/simple/decoy-1.0-py3-none-any.whl///")
			cache := &MetadataCache{}
			if test.established {
				cache.RegisterProject(*endpoint, "my-project", nil)
			}
			if err := cache.Observe(*endpoint, http.Header{"Content-Type": {"application/json"}}, []byte(readPyPIJSONFixture(t, test.fixture))); err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse("https://index.example/files/recent?token=one")
			artifact, found := cache.ArtifactForURL(target)
			wantDate := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
			if date, dated := cache.PublishDate(artifact); !found || artifact.Name != "my-project" || artifact.Version != "1.0" || !dated || date != wantDate {
				t.Fatalf("artifact=%#v found=%v date=%v; expected JSON identity and exact upload time", artifact, found, date)
			}
			if project, _, found := cache.ProjectForURL(endpoint); !found || project != "my-project" {
				t.Fatalf("metadata project=%q, found=%v; must come from established context or JSON", project, found)
			}
			other, _ := url.Parse("https://index.example/files/recent?token=two")
			if _, found := cache.ArtifactForURL(other); found {
				t.Fatal("publication evidence leaked into a different advertised URL")
			}
		})
	}
}

func TestPyPIMetadataCacheRequiresRecognizedJSONStructure(t *testing.T) {
	for _, fixture := range []string{"metadata/unrelated-json", "metadata/null-collections"} {
		t.Run(fixture, func(t *testing.T) {
			endpoint, _ := url.Parse("https://index.example/simple/decoy-1.0-py3-none-any.whl/")
			cache := &MetadataCache{}
			if err := cache.Observe(*endpoint, http.Header{"Content-Type": {"application/json"}}, []byte(readPyPIJSONFixture(t, fixture))); err != nil {
				t.Fatal(err)
			}
			if cache.HasObserved(*endpoint) {
				t.Fatal("unrecognized JSON marked as registry metadata")
			}
			if _, _, found := cache.ProjectForURL(endpoint); found {
				t.Fatal("unrecognized JSON established project context")
			}
		})
	}
}

func TestPyPIMetadataCacheRequiresAdvertisedArtifactURL(t *testing.T) {
	endpoint, _ := url.Parse("https://index.example/simple/decoy-1.0-py3-none-any.whl/")
	cache := &MetadataCache{}
	if err := cache.Observe(*endpoint, http.Header{"Content-Type": {"application/json"}}, []byte(readPyPIJSONFixture(t, "metadata/missing-artifact-url"))); err != nil {
		t.Fatal(err)
	}
	if artifact, found := cache.ArtifactForURL(endpoint); found {
		t.Fatalf("missing URL turned the metadata endpoint into an advertised artifact: %#v", artifact)
	}
}
