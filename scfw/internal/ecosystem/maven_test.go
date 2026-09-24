// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIsMavenRegistrySource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "canonical Maven Central", source: "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar", want: true},
		{name: "legacy Maven Central", source: "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.pom", want: true},
		{name: "http scheme", source: "http://repo.maven.apache.org/maven2/a/b/1/b-1.jar", want: true},
		{name: "unrelated domain", source: "https://example.com/maven2/a/b/1/b-1.jar"},
		{name: "unsupported scheme", source: "ftp://repo.maven.apache.org/maven2/a/b/1/b-1.jar"},
		{name: "malformed URL", source: "not a url"},
		{name: "empty string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isMavenRegistrySource(test.source); got != test.want {
				t.Fatalf("isMavenRegistrySource(%q) = %v, want %v", test.source, got, test.want)
			}
		})
	}
}

func TestParseMavenSearchResponse(t *testing.T) {
	want := time.Date(2024, 8, 24, 12, 9, 47, 0, time.UTC)
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "timestamp", body: `{"response":{"docs":[{"timestamp":1724501387000}]}}`},
		{name: "no documents", body: `{"response":{"docs":[]}}`, wantErr: true},
		{name: "missing timestamp", body: `{"response":{"docs":[{}]}}`, wantErr: true},
		{name: "malformed JSON", body: `not json`, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseMavenSearchResponse([]byte(test.body), "org.apache.commons:commons-lang3", "3.17.0")
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseMavenSearchResponse() = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMavenSearchResponse() returned error: %v", err)
			}
			if !got.Equal(want) {
				t.Fatalf("parseMavenSearchResponse() = %v, want %v", got, want)
			}
		})
	}
}

func TestResolveMavenPublishDateNonRegistrySourceIsNoop(t *testing.T) {
	got, err := resolveMavenPublishDate(context.Background(), "org.example:example", "1.0.0", "https://example.com/example-1.0.0.jar")
	if err != nil {
		t.Fatalf("resolveMavenPublishDate() returned error: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("resolveMavenPublishDate() = %v, want zero time", got)
	}
}

func TestResolveMavenPublishDateRejectsInvalidName(t *testing.T) {
	if _, err := resolveMavenPublishDate(context.Background(), "missing-group", "1.0.0", ""); err == nil {
		t.Fatal("resolveMavenPublishDate() returned nil error for invalid package name")
	}
}

func TestResolveMavenPublishDateUsesArtifactLastModified(t *testing.T) {
	want := time.Date(2024, 8, 24, 19, 6, 28, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("request method = %q, want HEAD", request.Method)
		}
		response.Header().Set("Last-Modified", want.Format(http.TimeFormat))
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse(server URL) returned error: %v", err)
	}
	previousDomains := mavenRegistryDomains
	mavenRegistryDomains = []string{serverURL.Hostname()}
	t.Cleanup(func() { mavenRegistryDomains = previousDomains })

	got, err := resolveMavenPublishDate(context.Background(), "org.example:example", "1.0.0", server.URL+"/maven2/org/example/example/1.0.0/example-1.0.0.jar")
	if err != nil {
		t.Fatalf("resolveMavenPublishDate() returned error: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("resolveMavenPublishDate() = %v, want %v", got, want)
	}
}

func TestResolveMavenPublishDateFallsBackToSearchWithoutSource(t *testing.T) {
	want := time.Date(2024, 8, 24, 12, 9, 47, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		if query.Get("core") != "gav" || query.Get("q") != `g:"org.example" AND a:"example" AND v:"1.0.0"` {
			t.Errorf("query = %q", request.URL.RawQuery)
		}
		_, _ = response.Write([]byte(`{"response":{"docs":[{"timestamp":1724501387000}]}}`))
	}))
	defer server.Close()
	previousEndpoint := mavenSearchEndpoint
	mavenSearchEndpoint = server.URL
	t.Cleanup(func() { mavenSearchEndpoint = previousEndpoint })

	got, err := resolveMavenPublishDate(context.Background(), "org.example:example", "1.0.0", "")
	if err != nil {
		t.Fatalf("resolveMavenPublishDate() returned error: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("resolveMavenPublishDate() = %v, want %v", got, want)
	}
}
