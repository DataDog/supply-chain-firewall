// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestParsePyPIDistributionFilename(t *testing.T) {
	tests := []struct {
		filename    string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{filename: "Django-5.1.2-py3-none-any.whl", wantName: "django", wantVersion: "5.1.2", wantOK: true},
		{filename: "zope_interface-7.1.0-2-cp313-cp313-manylinux_2_17_x86_64.whl", wantName: "zope-interface", wantVersion: "7.1.0", wantOK: true},
		{filename: "example_pkg-2.0rc1-py2.py3-none-any.whl", wantName: "example-pkg", wantVersion: "2.0rc1", wantOK: true},
		{filename: "Example_Pkg-01.0RC01-2-py2.py3-abi3-manylinux_2_17_x86_64.macosx_11_0_arm64.whl", wantName: "example-pkg", wantVersion: "1.0rc1", wantOK: true},
		{filename: "example_pkg-1.0-1.foo-py3-none-any.whl", wantName: "example-pkg", wantVersion: "1.0", wantOK: true},
		{filename: "example_pkg-1.0_preview-py3-none-any.whl", wantName: "example-pkg", wantVersion: "1.0rc0", wantOK: true},
		{filename: "my-normalized.name-1!2.0.post1.dev2+linux.tar.gz", wantName: "my-normalized-name", wantVersion: "1!2.0.post1.dev2+linux", wantOK: true},
		{filename: "legacy-project-name-1.0-2.zip", wantName: "legacy-project-name-1-0", wantVersion: "2", wantOK: true},
		{filename: "project-1-2.tar.gz", wantName: "project-1", wantVersion: "2", wantOK: true},
		{filename: "legacy-project-1.0-rc1.tar.gz", wantName: "legacy-project", wantVersion: "1.0rc1", wantOK: true},
		{filename: "Legacy.Project-v01.0_rev02+LINUX_001.tar.gz", wantName: "legacy-project", wantVersion: "1.0.post2+linux.1", wantOK: true},
		{filename: "project-1.0rc1.tar.bz2", wantName: "project", wantVersion: "1.0rc1", wantOK: true},
		{filename: "project-1.0dev.tar.gz", wantName: "project", wantVersion: "1.0.dev0", wantOK: true},
		{filename: "project-1.0.tar.xz", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "project-1.0.tar", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "project-1.0.tbz", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "project-1.0.txz", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "project-1.0.tlz", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "project-1.0.tar.lz", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "project-1.0.tar.lzma", wantName: "project", wantVersion: "1.0", wantOK: true},
		{filename: "not-a-distribution.txt", wantOK: false},
		{filename: "missing-tags-1.0.whl", wantOK: false},
		{filename: "project-not-a-version.tar.gz", wantOK: false},
		{filename: "project-1..0.tar.gz", wantOK: false},
		{filename: "project-1.0-final.tar.gz", wantOK: false},
		{filename: "bad+name-1.0.tar.gz", wantOK: false},
		{filename: "project-1.0-py3-none.whl", wantOK: false},
		{filename: "project-1.0-build-py3-none-any.whl", wantOK: false},
		{filename: "project-1.0-.py3-none-any.whl", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			name, version, ok := ParsePyPIDistributionFilename(tt.filename)
			if name != tt.wantName || version != tt.wantVersion || ok != tt.wantOK {
				t.Fatalf("ParsePyPIDistributionFilename(%q) = %q, %q, %v; want %q, %q, %v",
					tt.filename, name, version, ok, tt.wantName, tt.wantVersion, tt.wantOK)
			}
		})
	}
}

func TestPyPIVersionIdentityIgnoresReleaseTrailingZeros(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{version: "1.0", want: "1"},
		{version: "1.0.0", want: "1"},
		{version: "01.0.0RC01", want: "1rc1"},
		{version: "1.0rc1", want: "1rc1"},
		{version: "2!1.0.0.post2+LINUX_001", want: "2!1.post2+linux.1"},
	}
	for _, tt := range tests {
		if got := PyPIVersionIdentity(tt.version); got != tt.want {
			t.Errorf("PyPIVersionIdentity(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestClassifyPyPIRequest(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		url        string
		wantKind   PyPIRequestKind
		wantName   string
		wantSource string
	}{
		{name: "JSON API", method: http.MethodGet, url: "https://pypi.org/pypi/requests/json", wantKind: PyPIRequestJSONAPI},
		{name: "version JSON API", method: http.MethodGet, url: "https://pypi.org/pypi/requests/2.32.3/json", wantKind: PyPIRequestJSONAPI},
		{name: "HTML Simple API", method: http.MethodGet, url: "https://pypi.org/simple/requests/", wantKind: PyPIRequestSimpleAPI},
		{name: "custom JSON Simple API", method: http.MethodGet, url: "https://token@example.test/simple/requests/", wantKind: PyPIRequestSimpleAPI},
		{name: "Artifactory Simple API", method: http.MethodGet, url: "https://artifactory.example/api/pypi/repo/simple/requests/", wantKind: PyPIRequestSimpleAPI},
		{name: "prefixed Artifactory Simple API", method: http.MethodGet, url: "https://artifactory.example/artifactory/api/pypi/repo/simple/requests/", wantKind: PyPIRequestSimpleAPI},
		{name: "devpi Simple API", method: http.MethodGet, url: "https://devpi.example/user/index/+simple/requests/", wantKind: PyPIRequestSimpleAPI},
		{name: "artifact beneath official Simple path", method: http.MethodGet, url: "https://pypi.org/simple/files/project-1.0.tar.gz", wantKind: PyPIRequestArtifact, wantName: "project", wantSource: "https://pypi.org/simple/files/project-1.0.tar.gz"},
		{name: "unconfigured archive beneath Simple-like path", method: http.MethodGet, url: "https://index.example/simple/files/project-1.0.tar.gz", wantKind: PyPIRequestUnrelated},
		{
			name:       "official wheel",
			method:     http.MethodGet,
			url:        "https://files.pythonhosted.org/packages/requests-2.32.3-py3-none-any.whl",
			wantKind:   PyPIRequestArtifact,
			wantName:   "requests",
			wantSource: "https://files.pythonhosted.org/packages/requests-2.32.3-py3-none-any.whl",
		},
		{name: "unadvertised custom archive", method: http.MethodGet, url: "https://user:password@cdn.example.test/pkg/My_Pkg-1.0rc1.tar.gz?token=secret", wantKind: PyPIRequestUnrelated},
		{name: "wheel core metadata", method: http.MethodGet, url: "https://files.pythonhosted.org/packages/requests-2.32.3-py3-none-any.whl.metadata", wantKind: PyPIRequestCoreMetadata},
		{name: "artifact HEAD", method: http.MethodHead, url: "https://files.pythonhosted.org/pkg/requests-2.32.3.tar.gz", wantKind: PyPIRequestUnrelated},
		{name: "unrelated nested simple path", method: http.MethodGet, url: "https://example.test/docs/simple/requests/", wantKind: PyPIRequestUnrelated},
		{name: "unrelated Artifactory-like path", method: http.MethodGet, url: "https://example.test/api/pypi/repo/not-simple/requests/", wantKind: PyPIRequestUnrelated},
		{name: "unrelated prefixed Artifactory lookalike", method: http.MethodGet, url: "https://example.test/prefix/artifactory/api/pypi/repo/simple/requests/", wantKind: PyPIRequestUnrelated},
		{name: "unrelated archive under lookalike", method: http.MethodGet, url: "https://example.test/prefix/artifactory/api/pypi/repo/simple/report-2026.zip", wantKind: PyPIRequestUnrelated},
		{name: "unrelated", method: http.MethodGet, url: "https://example.test/index.json", wantKind: PyPIRequestUnrelated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestURL, err := url.Parse(tt.url)
			if err != nil {
				t.Fatal(err)
			}
			kind, artifact := ClassifyPyPIRequest(tt.method, requestURL)
			if kind != tt.wantKind || artifact.Name != tt.wantName || artifact.Source != tt.wantSource {
				t.Fatalf("ClassifyPyPIRequest() = %v, %#v; want kind %v, name %q, source %q",
					kind, artifact, tt.wantKind, tt.wantName, tt.wantSource)
			}
		})
	}
}

func TestPyPIRequestClassifierConfiguredContexts(t *testing.T) {
	classifier, err := NewPyPIRequestClassifier(PyPIRequestClassifierOptions{
		SimpleIndexURLs: []string{
			"https://index.example/python-packages/",
			"https://json.example/simple/v1+json/",
		},
		DirectArtifactURLs: []string{
			"https://user:secret@cdn.example/download/report-2026.zip?id=artifact&token=secret",
			"https://cdn.example/download/project-1.0-py3-none-any.whl?id=wheel",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		value    string
		wantKind PyPIRequestKind
		wantName string
	}{
		{name: "arbitrary HTML base", value: "https://index.example/python-packages/My_Project/", wantKind: PyPIRequestSimpleAPI},
		{name: "arbitrary JSON base", value: "https://json.example/simple/v1+json/my-project/", wantKind: PyPIRequestSimpleAPI},
		{name: "unadvertised configured-origin artifact", value: "https://index.example/files/my_project-1.0.txz", wantKind: PyPIRequestUnrelated},
		{name: "unadvertised configured-origin core metadata", value: "https://index.example/files/my_project-1.0-py3-none-any.whl.metadata", wantKind: PyPIRequestUnrelated},
		{name: "direct exact URL without transport credentials", value: "https://cdn.example/download/report-2026.zip?id=artifact&token=secret", wantKind: PyPIRequestArtifact, wantName: "report"},
		{name: "direct wheel core metadata", value: "https://cdn.example/download/project-1.0-py3-none-any.whl.metadata?id=wheel", wantKind: PyPIRequestCoreMetadata},
		{name: "direct query mismatch", value: "https://user:secret@cdn.example/download/report-2026.zip?id=other&token=secret", wantKind: PyPIRequestUnrelated},
		{name: "unrelated archive", value: "https://unrelated.example/report-2026.zip", wantKind: PyPIRequestUnrelated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestURL, parseErr := url.Parse(test.value)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			kind, artifact := classifier.ClassifyRequest(http.MethodGet, requestURL)
			if kind != test.wantKind || artifact.Name != test.wantName {
				t.Fatalf("ClassifyRequest() = %v, %#v; want %v, name %q", kind, artifact, test.wantKind, test.wantName)
			}
		})
	}
	candidateURL, err := url.Parse("https://cdn.example/files/My_Project-2.0.tar.gz?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	project, endpoints, ok := classifier.MetadataDiscovery(candidateURL)
	if !ok || project != "my-project" || len(endpoints) != 2 ||
		endpoints[0].String() != "https://index.example/python-packages/my-project/" ||
		endpoints[1].String() != "https://json.example/simple/v1+json/my-project/" {
		t.Fatalf("MetadataDiscovery() = %q, %v, %v", project, endpoints, ok)
	}
}

func TestPyPIRequestClassifierUsesProtocolMediaTypeEvidence(t *testing.T) {
	classifier, err := NewPyPIRequestClassifier(PyPIRequestClassifierOptions{})
	if err != nil {
		t.Fatal(err)
	}
	requestURL, err := url.Parse("https://index.example/python-packages/project/")
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}
	kind, _ := classifier.ClassifyResponse(http.MethodGet, requestURL, header)
	if kind != PyPIRequestSimpleAPI {
		t.Fatalf("ClassifyResponse() = %v, want Simple API", kind)
	}
	project, ok := classifier.SimpleProject(requestURL, header)
	if !ok || project != "project" {
		t.Fatalf("SimpleProject() = %q, %v, want project, true", project, ok)
	}

	kind, _ = classifier.ClassifyResponse(http.MethodGet, requestURL, http.Header{"Content-Type": []string{"application/json"}})
	if kind != PyPIRequestUnrelated {
		t.Fatalf("generic JSON ClassifyResponse() = %v, want unrelated", kind)
	}
}

func TestIsPyPIRegistrySource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "pypi.org", source: "https://pypi.org/simple/six/", want: true},
		{name: "files.pythonhosted.org", source: "https://files.pythonhosted.org/packages/six-1.16.0.whl", want: true},
		{name: "http scheme", source: "http://pypi.org/simple/six/", want: true},
		{name: "unrelated domain", source: "https://example.com/six-1.16.0.whl", want: false},
		{name: "unsupported scheme", source: "ftp://pypi.org/simple/six/", want: false},
		{name: "malformed URL", source: "not a url", want: false},
		{name: "empty string", source: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPyPIRegistrySource(tc.source); got != tc.want {
				t.Fatalf("isPyPIRegistrySource(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

func TestParsePyPIReleaseMetadata(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		version string
		wantErr bool
		want    time.Time
	}{
		{
			name:    "single upload timestamp",
			body:    `{"releases": {"1.16.0": [{"upload_time_iso_8601": "2021-05-05T09:00:00.000000Z"}]}}`,
			version: "1.16.0",
			want:    time.Date(2021, 5, 5, 9, 0, 0, 0, time.UTC),
		},
		{
			name:    "latest of multiple upload timestamps",
			body:    `{"releases": {"1.16.0": [{"upload_time_iso_8601": "2021-05-05T09:00:00.000000Z"}, {"upload_time_iso_8601": "2021-05-05T10:00:00.000000Z"}]}}`,
			version: "1.16.0",
			want:    time.Date(2021, 5, 5, 10, 0, 0, 0, time.UTC),
		},
		{
			name:    "missing version",
			body:    `{"releases": {"1.16.0": [{"upload_time_iso_8601": "2021-05-05T09:00:00.000000Z"}]}}`,
			version: "9.9.9",
			wantErr: true,
		},
		{
			name:    "empty release list",
			body:    `{"releases": {"1.16.0": []}}`,
			version: "1.16.0",
			wantErr: true,
		},
		{
			name:    "missing upload timestamps",
			body:    `{"releases": {"1.16.0": [{"upload_time_iso_8601": ""}]}}`,
			version: "1.16.0",
			wantErr: true,
		},
		{
			name:    "malformed timestamp",
			body:    `{"releases": {"1.16.0": [{"upload_time_iso_8601": "not a timestamp"}]}}`,
			version: "1.16.0",
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			body:    `not json`,
			version: "1.16.0",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePyPIReleaseMetadataForArtifact([]byte(tc.body), "six", tc.version, "")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePyPIReleaseMetadataForArtifact(%q, %q) = %v, want error", tc.body, tc.version, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePyPIReleaseMetadataForArtifact(%q, %q) returned unexpected error: %v", tc.body, tc.version, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parsePyPIReleaseMetadataForArtifact(%q, %q) = %v, want %v", tc.body, tc.version, got, tc.want)
			}
		})
	}
}

func TestParsePyPIReleaseMetadataSelectsExactArtifact(t *testing.T) {
	body := []byte(`{"releases":{"1.0":[` +
		`{"filename":"project-1.0.tar.gz","upload_time_iso_8601":"2025-01-01T01:00:00Z"},` +
		`{"filename":"project-1.0-py3-none-any.whl","upload_time_iso_8601":"2025-01-02T02:00:00Z"}]}}`)

	got, err := parsePyPIReleaseMetadataForArtifact(body, "project", "1.0", "project-1.0.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("exact artifact timestamp = %v, want %v", got, want)
	}
	if _, err := parsePyPIReleaseMetadataForArtifact(body, "project", "1.0", "missing-1.0.tar.gz"); err == nil {
		t.Fatal("missing exact artifact returned nil error")
	}
}

func TestExactArtifactLookupRetainsReleaseTrailingZeros(t *testing.T) {
	name, version, ok := ParsePyPIDistributionFilename("project-1.0.0-py3-none-any.whl")
	if !ok || name != "project" || version != "1.0.0" {
		t.Fatalf("parsed artifact = %q, %q, %v; want project, 1.0.0, true", name, version, ok)
	}
	body := []byte(`{"releases":{"1.0.0":[` +
		`{"filename":"project-1.0.0-py3-none-any.whl","upload_time_iso_8601":"2025-02-03T04:05:06Z"}]}}`)
	got, err := parsePyPIReleaseMetadataForArtifact(body, name, version, "project-1.0.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("exact trailing-zero artifact timestamp = %v, want %v", got, want)
	}
}

func TestResolvePyPIPublishDateWithClientUsesSuppliedTransport(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.String() != "https://pypi.org/pypi/project/json" {
			t.Fatalf("request URL = %q, want project JSON API", request.URL)
		}
		body := `{"releases":{"1.0":[{"filename":"project-1.0.tar.gz","upload_time_iso_8601":"2025-01-02T03:04:05Z"}]}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}
	got, err := ResolvePyPIPublishDateWithClient(
		context.Background(),
		client,
		"project",
		"1.0",
		"https://files.pythonhosted.org/packages/project-1.0.tar.gz",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if !got.Equal(want) || requests != 1 {
		t.Fatalf("publish date=%v requests=%d; want %v, 1", got, requests, want)
	}
}

func TestResolvePyPIPublishDate_NonRegistrySourceIsNoop(t *testing.T) {
	got, err := resolvePyPIPublishDate(context.Background(), "six", "1.16.0", "https://example.com/six-1.16.0.whl")
	if err != nil {
		t.Fatalf("resolvePyPIPublishDate() returned unexpected error: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("resolvePyPIPublishDate() = %v, want zero time", got)
	}
}

func TestResolvePyPIPublishDate_RealPyPI(t *testing.T) {
	const (
		name    = "requests"
		version = "2.32.3"
	)
	want := time.Date(2024, 5, 29, 15, 37, 49, 536140000, time.UTC)

	tests := []struct {
		name   string
		source string
	}{
		{name: "pypi.org source", source: "https://pypi.org/project/requests/2.32.3/"},
		{
			name:   "files.pythonhosted.org source",
			source: "https://files.pythonhosted.org/packages/63/70/2bf7780ad2d390a8d301ad0b550f1581eadbd9a20f896afe06353c2a2913/requests-2.32.3.tar.gz",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			got, err := resolvePyPIPublishDate(ctx, name, version, tc.source)
			if err != nil {
				t.Fatalf("resolvePyPIPublishDate(%q, %q, %q) returned unexpected error: %v", name, version, tc.source, err)
			}
			if !got.Equal(want) {
				t.Fatalf("resolvePyPIPublishDate(%q, %q, %q) = %v, want %v", name, version, tc.source, got, want)
			}
		})
	}
}

func TestResolvePyPIPublishDate_RealPyPI_NonexistentPackage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const name = "this-package-definitely-does-not-exist-xyz"

	got, err := resolvePyPIPublishDate(ctx, name, "1.0.0", "")
	if err == nil {
		t.Fatalf("resolvePyPIPublishDate(%q, ...) = %v, want error", name, got)
	}
}
