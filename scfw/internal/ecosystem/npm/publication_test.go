// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	leftPad120Date = time.Date(2017, 11, 17, 5, 48, 38, 934000000, time.UTC)
	leftPad130Date = time.Date(2018, 4, 9, 1, 10, 45, 796000000, time.UTC)
)

func leftPadPackument(t *testing.T) string {
	t.Helper()
	return readNpmJSONFixture(t, "packument/left-pad")
}

// registryArtifact classifies the tarball at registryBase+tarballPath with
// registryBase configured as a registry.
func registryArtifact(t *testing.T, registryBase, tarballPath string) Artifact {
	t.Helper()
	classifier, err := NewClassifier(ClassifierOptions{RegistryURLs: []string{registryBase}})
	if err != nil {
		t.Fatalf("NewClassifier() returned unexpected error: %v", err)
	}
	kind, artifact := classifier.Classify(mustParseURL(t, strings.TrimSuffix(registryBase, "/")+tarballPath))
	if kind != RequestTarball {
		t.Fatalf("%s%s is not classified as a tarball", registryBase, tarballPath)
	}
	return artifact
}

func servePackument(body string, hits *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestResolveReturnsPublishDate(t *testing.T) {
	var accept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		servePackument(leftPadPackument(t), nil)(w, r)
	}))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	date, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact)
	if err != nil {
		t.Fatalf("Resolve() returned unexpected error: %v", err)
	}
	if !date.Equal(leftPad130Date) {
		t.Fatalf("Resolve() = %v, want %v", date, leftPad130Date)
	}
	if accept != "application/json" {
		t.Fatalf("packument request Accept = %q, want application/json (the full packument)", accept)
	}
}

func TestResolveFetchesScopedPackumentEscaped(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		servePackument(readNpmJSONFixture(t, "packument/babel-helper-string-parser"), nil)(w, r)
	}))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/", "/@babel/helper-string-parser/-/helper-string-parser-7.25.9.tgz")
	if _, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact); err != nil {
		t.Fatalf("Resolve() returned unexpected error: %v", err)
	}
	if path != "/@babel%2Fhelper-string-parser" {
		t.Fatalf("packument path = %q, want /@babel%%2Fhelper-string-parser", path)
	}
}

func TestResolveKeepsRegistryPathPrefix(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		servePackument(leftPadPackument(t), nil)(w, r)
	}))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/artifactory/api/npm/npm-remote/", "/left-pad/-/left-pad-1.3.0.tgz")
	if _, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact); err != nil {
		t.Fatalf("Resolve() returned unexpected error: %v", err)
	}
	if path != "/artifactory/api/npm/npm-remote/left-pad" {
		t.Fatalf("packument path = %q, want /artifactory/api/npm/npm-remote/left-pad", path)
	}
}

func TestResolveForwardsAuthorizationOnlySameOrigin(t *testing.T) {
	var targetAuthorization atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetAuthorization.Store(r.Header.Get("Authorization"))
		servePackument(leftPadPackument(t), nil)(w, r)
	}))
	defer target.Close()

	var origin http.Header
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin = r.Header.Clone()
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer registry.Close()

	artifact := registryArtifact(t, registry.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	artifact.authorization = "Bearer t0k3n"
	if _, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact); err != nil {
		t.Fatalf("Resolve() returned unexpected error: %v", err)
	}
	if got := origin.Get("Authorization"); got != "Bearer t0k3n" {
		t.Fatalf("same-origin Authorization = %q, want the tarball request's token", got)
	}
	if got, _ := targetAuthorization.Load().(string); got != "" {
		t.Fatalf("cross-origin redirect received Authorization %q, want none", got)
	}
}

func TestResolveDecodesGzip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			servePackument(leftPadPackument(t), nil)(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte(leftPadPackument(t)))
		_ = writer.Close()
	}))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	date, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact)
	if err != nil || !date.Equal(leftPad130Date) {
		t.Fatalf("Resolve() = %v, %v; want %v from a gzip-encoded packument", date, err, leftPad130Date)
	}
}

func TestResolveRejectsOversizedPackument(t *testing.T) {
	original := maxPackumentBytes
	maxPackumentBytes = 1024
	t.Cleanup(func() { maxPackumentBytes = original })

	server := httptest.NewServer(servePackument(`{"readme":"`+strings.Repeat("x", 2048)+`"}`, nil))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	if _, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact); err == nil {
		t.Fatal("Resolve() returned nil error for a packument over the size limit")
	}
}

func TestResolveTimesOut(t *testing.T) {
	original := packumentFetchTimeout
	packumentFetchTimeout = 50 * time.Millisecond
	t.Cleanup(func() { packumentFetchTimeout = original })

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}
	}))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	started := time.Now()
	_, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact)
	if err == nil {
		t.Fatal("Resolve() returned nil error for a registry slower than the timeout")
	}
	// A slow registry is a publication failure, not a cancellation: policy
	// callers treat context errors as "stop", which would reject the download.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() timeout error = %v, want a non-context publication error", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("Resolve() took %v, want it bounded by the fetch timeout", elapsed)
	}
}

func TestResolveFetchesOncePerPackageAcrossVersionsAndConcurrency(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		servePackument(leftPadPackument(t), &hits)(w, r)
	}))
	defer server.Close()

	cache := &PublicationCache{}
	versions := map[string]time.Time{"1.2.0": leftPad120Date, "1.3.0": leftPad130Date}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := range 10 {
		version := "1.2.0"
		if i%2 == 1 {
			version = "1.3.0"
		}
		artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-"+version+".tgz")
		wg.Go(func() {
			date, err := cache.Resolve(context.Background(), http.DefaultClient, artifact)
			if err == nil && !date.Equal(versions[artifact.Version]) {
				err = errors.New("wrong publish date for " + artifact.Version)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("packument fetched %d times, want once per package per run", hits.Load())
	}
}

func TestResolveCachesFailures(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cache := &PublicationCache{}
	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	for range 2 {
		if _, err := cache.Resolve(context.Background(), http.DefaultClient, artifact); err == nil {
			t.Fatal("Resolve() returned nil error for a failing registry")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("failing packument fetched %d times, want the failure cached for the run", hits.Load())
	}
}

func TestResolveDoesNotCacheCancellation(t *testing.T) {
	server := httptest.NewServer(servePackument(leftPadPackument(t), nil))
	defer server.Close()

	cache := &PublicationCache{}
	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-1.3.0.tgz")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.Resolve(canceled, http.DefaultClient, artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() with a canceled context = %v, want context.Canceled", err)
	}
	date, err := cache.Resolve(context.Background(), http.DefaultClient, artifact)
	if err != nil || !date.Equal(leftPad130Date) {
		t.Fatalf("Resolve() after a canceled attempt = %v, %v; want %v", date, err, leftPad130Date)
	}
}

func TestResolveReportsMissingVersion(t *testing.T) {
	server := httptest.NewServer(servePackument(leftPadPackument(t), nil))
	defer server.Close()

	artifact := registryArtifact(t, server.URL+"/", "/left-pad/-/left-pad-9.9.9.tgz")
	if _, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact); err == nil {
		t.Fatal("Resolve() for an unlisted version returned nil error")
	}
}

func TestResolveErrorsOmitURLs(t *testing.T) {
	originalTimeout, originalLimit := packumentFetchTimeout, maxPackumentBytes
	packumentFetchTimeout, maxPackumentBytes = 50*time.Millisecond, 1024
	t.Cleanup(func() { packumentFetchTimeout, maxPackumentBytes = originalTimeout, originalLimit })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/oversized":
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		case "/slow":
			select {
			case <-time.After(time.Second):
			case <-r.Context().Done():
			}
		}
	}))
	defer server.Close()

	host := mustParseURL(t, server.URL).Host
	for _, name := range []string{"missing", "oversized", "slow"} {
		artifact := registryArtifact(t, server.URL+"/", "/"+name+"/-/"+name+"-1.0.0.tgz")
		artifact.authorization = "Bearer t0k3n"
		_, err := (&PublicationCache{}).Resolve(context.Background(), http.DefaultClient, artifact)
		if err == nil {
			t.Fatalf("%s: Resolve() returned nil error", name)
		}
		if strings.Contains(err.Error(), host) || strings.Contains(err.Error(), "t0k3n") {
			t.Fatalf("%s: error %q exposes the registry URL or credentials", name, err)
		}
	}
}
