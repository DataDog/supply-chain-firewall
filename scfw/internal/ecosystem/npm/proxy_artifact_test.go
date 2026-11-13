// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyArtifactResponses(t *testing.T) {
	for _, mode := range []string{"matched", "mismatched", "opaque", "opaque redirect", "redirect", "range", "conditional", "changed bytes", "observed disagreement", "abbreviated distribution", "encoded observed"} {
		t.Run(mode, func(t *testing.T) {
			body := fixtureTar(t, []string{"package/package.json"}, 0)
			source := ""
			var upstream *httptest.Server
			upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/fixture" {
					m := map[string]any{"name": "fixture", "version": "1.0.0", "dist": map[string]any{"tarball": source}}
					if mode == "abbreviated distribution" && r.Header.Get("Accept") == "application/json" {
						sum := sha1.Sum(body)
						m["dist"].(map[string]any)["shasum"] = hex.EncodeToString(sum[:])
					}
					if mode == "mismatched" {
						m["dependencies"] = map[string]string{"extra": "1"}
					}
					if mode == "observed disagreement" && r.Header.Get("Accept") != "application/json" {
						m["scripts"] = map[string]string{"install": "observed-only"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"name": "fixture", "time": map[string]string{"1.0.0": "2025-01-01T00:00:00Z"}, "versions": map[string]any{"1.0.0": m}})
					return
				}
				if mode == "opaque redirect" && r.URL.Path == "/opaque" {
					http.Redirect(w, r, "/final/fixture/-/fixture-1.0.0.tgz", 302)
					return
				}
				if mode == "redirect" && r.URL.Path != "/final" {
					http.Redirect(w, r, "/final", 302)
					return
				}
				if mode == "range" {
					w.WriteHeader(206)
				}
				if mode == "conditional" {
					w.WriteHeader(304)
					return
				}
				if mode == "encoded observed" {
					w.Header().Set("Content-Encoding", "gzip")
					gz := gzip.NewWriter(w)
					_, _ = gz.Write(body)
					_ = gz.Close()
					return
				}
				_, _ = w.Write(body)
			}))
			defer upstream.Close()
			source = upstream.URL + "/fixture/-/fixture-1.0.0.tgz"
			if mode == "opaque" || mode == "opaque redirect" {
				source = upstream.URL + "/opaque"
			}
			var mu sync.Mutex
			var results []pm.ArtifactResult
			hook, e := NewProxyHook(context.Background(), ProxyHookOptions{Client: upstream.Client(), ClassifierOptions: ClassifierOptions{RegistryURLs: []string{upstream.URL}}, RegistryArtifact: func(name, version, url string) (Artifact, error) {
				return MetadataArtifact(upstream.URL, name, version, url)
			}, EvaluatePackage: func(context.Context, pm.Package, error) error { return nil }, EvaluateResult: func(_ context.Context, result pm.ArtifactResult) error {
				mu.Lock()
				defer mu.Unlock()
				results = append(results, result)
				if result.Status != pm.ArtifactMatched && result.Status != pm.ArtifactNotApplicable {
					return proxy.ErrResponseRejected
				}
				return nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			client := proxiedClient(t, hook)
			if mode == "observed disagreement" || mode == "abbreviated distribution" || mode == "encoded observed" {
				response, e := client.Get(upstream.URL + "/fixture")
				if e != nil {
					t.Fatal(e)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
			response, e := client.Get(source)
			if e != nil {
				t.Fatal(e)
			}
			received, e := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if e != nil {
				t.Fatal(e)
			}
			blocked := mode == "mismatched" || mode == "range" || mode == "conditional" || mode == "observed disagreement"
			if blocked {
				if response.StatusCode != 403 || bytes.Equal(received, body) {
					t.Fatalf("artifact was not withheld, status=%d", response.StatusCode)
				}
			} else if response.StatusCode != 200 || !bytes.Equal(received, body) {
				t.Fatalf("matching bytes changed: status %d", response.StatusCode)
			}
			if mode == "changed bytes" {
				body = fixtureTar(t, []string{"package/example/package.json"}, 0)
				response, e = client.Get(source)
				if e != nil {
					t.Fatal(e)
				}
				_ = response.Body.Close()
				if response.StatusCode != 403 {
					t.Fatal("cached success authorized changed bytes")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(results) == 0 {
				t.Fatal("artifact was never inspected")
			}
		})
	}
}
func TestCheckerEncodedDownloadAndLockIntegrity(t *testing.T) {
	body := fixtureTar(t, []string{"package/package.json"}, 0)
	var upstream *httptest.Server
	source := ""
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture" {
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "fixture", "versions": map[string]any{"1.0.0": map[string]any{"name": "fixture", "version": "1.0.0", "dist": map[string]string{"tarball": source}}}})
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write(body)
		_ = gz.Close()
	}))
	defer upstream.Close()
	source = upstream.URL + "/opaque"
	a, e := MetadataArtifact(upstream.URL, "fixture", "1.0.0", source)
	if e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: proxy.NewTransport(proxy.Options{})}
	defer client.CloseIdleConnections()
	checker := NewChecker(client, nil)
	result := checker.Fetch(context.Background(), a, source, "")
	if result.Status != pm.ArtifactMatched {
		t.Fatalf("HTTP encoded archive: %+v", result)
	}
	result = checker.Fetch(context.Background(), a, source, "sha512-"+strings.Repeat("A", 86)+"==")
	if result.Status != pm.ArtifactMismatched {
		t.Fatalf("lock integrity not enforced: %+v", result)
	}
}
func TestProxyMetadataComparison(t *testing.T) {
	var cases map[string]struct {
		Full, Observed json.RawMessage
		Agrees         bool
	}
	if err := json.Unmarshal([]byte(readNpmJSONFixture(t, "metadata-comparison")), &cases); err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := metadataAgrees(c.Full, c.Observed); got != c.Agrees {
				t.Fatalf("metadata agreement=%v, want %v", got, c.Agrees)
			}
		})
	}
}

func TestProxyMetadataFieldSelection(t *testing.T) {
	var cases map[string]struct {
		Field         string
		First, Second json.RawMessage
		Compared      bool
	}
	if err := json.Unmarshal([]byte(readNpmJSONFixture(t, "manifest-field-selection")), &cases); err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			full, err := json.Marshal(map[string]json.RawMessage{c.Field: c.First})
			if err != nil {
				t.Fatal(err)
			}
			observed, err := json.Marshal(map[string]json.RawMessage{c.Field: c.Second})
			if err != nil {
				t.Fatal(err)
			}
			if got := metadataAgrees(full, observed); got == c.Compared {
				t.Fatalf("metadata agreement=%v, want %v", got, !c.Compared)
			}
		})
	}
}

func TestGitDiscoveryRequiresFraming(t *testing.T) {
	good := []byte("001e# service=git-upload-pack\n0000000eversion 2\n0000")
	for _, c := range []struct {
		body  []byte
		valid bool
	}{{good, true}, {[]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}, false}, {[]byte("not a Git response"), false}, {fixtureTar(t, []string{"package/package.json"}, 0), false}} {
		if got := validGitDiscovery(io.NewSectionReader(bytes.NewReader(c.body), 0, int64(len(c.body)))); got != c.valid {
			t.Fatalf("Git framing accepted=%v expected=%v", got, c.valid)
		}
	}
}

func TestHostedGitSourceIsNotARegistryPackage(t *testing.T) {
	metadataHits := 0
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		metadataHits++
		return nil, errors.New("registry lookup should not happen")
	})}
	var result pm.ArtifactResult
	hook, e := NewProxyHook(context.Background(), ProxyHookOptions{Client: client, ClassifierOptions: ClassifierOptions{RegistryURLs: []string{"https://registry.example/"}}, NonRegistrySources: []NonRegistrySource{{Name: "local-git", Source: "github:owner/repo#commit", ArchiveURLs: []string{"https://codeload.github.com/owner/repo/tar.gz/commit"}}}, EvaluatePackage: func(context.Context, pm.Package, error) error {
		t.Fatal("Git source received registry policy lookup")
		return nil
	}, EvaluateResult: func(_ context.Context, r pm.ArtifactResult) error { result = r; return nil }})
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse("https://codeload.github.com/owner/repo/tar.gz/commit")
	request := proxy.Request{Method: "GET", URL: *u}
	responseHook, e := hook(context.Background(), request)
	if e != nil || responseHook == nil {
		t.Fatalf("Git hook: %v", e)
	}
	body, e := responseHook(context.Background(), proxy.Response{Request: request, StatusCode: 200})
	if e != nil || body != nil || result.Status != pm.ArtifactNotApplicable || metadataHits != 0 {
		t.Fatalf("Git result=%+v error=%v", result, e)
	}
}

func TestGitRedirectIsAnExactRequestAssociation(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef01234567"
	source := "https://codeload.github.com/owner/repo/tar.gz/" + hash
	u, _ := url.Parse(source)
	header := http.Header{"Pacote-Req-Type": {"tarball"}, "Pacote-Pkg-Id": {"git:git+https://github.com/owner/repo.git#" + hash}}
	proof := NonRegistrySource{Name: "repo", Source: "git+https://github.com/owner/repo.git", Reference: hash, ArchiveURLs: []string{source}}
	hook, e := NewProxyHook(context.Background(), ProxyHookOptions{EvaluatePackage: func(context.Context, pm.Package, error) error { return nil }, ResolveNonRegistryRequest: func(request proxy.Request) (NonRegistrySource, bool) {
		return proof, strings.HasPrefix(request.Header.Get("pacote-pkg-id"), "git:")
	}, EvaluateResult: func(_ context.Context, result pm.ArtifactResult) error {
		if result.Status != pm.ArtifactNotApplicable {
			return proxy.ErrResponseRejected
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	request := proxy.Request{Method: "GET", URL: *u, Header: header}
	response, e := hook(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	_, e = response(context.Background(), proxy.Response{Request: request, StatusCode: 302, Header: http.Header{"Location": {"https://cdn.example/download/123?token=exact"}}})
	if e != nil {
		t.Fatal(e)
	}
	for _, uri := range []string{"https://cdn.example/download/123-other?token=exact", "https://cdn.example/download/123?token=different"} {
		u, _ := url.Parse(uri)
		request.URL = *u
		response, e = hook(context.Background(), request)
		if errors.Is(e, proxy.ErrResponseRejected) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		body, e := response(context.Background(), proxy.Response{Request: request, StatusCode: 200})
		if e != nil {
			t.Fatal(e)
		}
		if body == nil {
			t.Fatal("Git redirect broadened its URL permission")
		}
	}
	u, _ = url.Parse("https://cdn.example/download/123?token=exact")
	request.URL = *u
	request.Header = header.Clone()
	request.Header.Set("Pacote-Pkg-Id", "registry:other@"+request.URL.String())
	response, e = hook(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	body, e := response(context.Background(), proxy.Response{Request: request, StatusCode: 200})
	if e != nil {
		t.Fatal(e)
	}
	if body == nil {
		t.Fatal("registry request inherited a Git exemption")
	}
}

func TestProxyBufferingFailuresDoNotReserveInspectionSlots(t *testing.T) {
	body := fixtureTar(t, []string{"package/package.json"}, 0)
	previous := maxArtifactBytes
	maxArtifactBytes = int64(len(body))
	t.Cleanup(func() { maxArtifactBytes = previous })
	for _, path := range []string{"/fixture/-/fixture-1.0.0.tgz", "/opaque"} {
		t.Run(path, func(t *testing.T) {
			var oversized atomic.Bool
			oversized.Store(true)
			source := ""
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/fixture" {
					_ = json.NewEncoder(w).Encode(map[string]any{"name": "fixture", "versions": map[string]any{"1.0.0": map[string]any{"name": "fixture", "version": "1.0.0", "dist": map[string]string{"tarball": source}}}})
					return
				}
				_, _ = w.Write(body)
				if oversized.Load() {
					_, _ = w.Write([]byte{0})
				}
			}))
			defer upstream.Close()
			source = upstream.URL + path
			var inspected atomic.Int32
			hook, err := NewProxyHook(context.Background(), ProxyHookOptions{
				Client: upstream.Client(), ClassifierOptions: ClassifierOptions{RegistryURLs: []string{upstream.URL}},
				RegistryArtifact: func(name, version, source string) (Artifact, error) {
					return MetadataArtifact(upstream.URL, name, version, source)
				},
				EvaluatePackage: func(context.Context, pm.Package, error) error { return nil },
				EvaluateResult: func(_ context.Context, result pm.ArtifactResult) error {
					if result.Status != pm.ArtifactMatched {
						return proxy.ErrResponseRejected
					}
					inspected.Add(1)
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			client := proxiedClient(t, hook)
			// More buffering failures than inspection slots must not prevent a later check.
			for range 6 {
				response, err := client.Get(source)
				if err != nil {
					t.Fatal(err)
				}
				received, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusBadGateway || bytes.Contains(received, body) {
					t.Fatalf("buffering failure forwarded artifact: status=%d error=%v", response.StatusCode, err)
				}
			}
			oversized.Store(false)
			response, err := client.Get(source)
			if err != nil {
				t.Fatal(err)
			}
			received, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(received, body) || inspected.Load() != 1 {
				t.Fatalf("subsequent inspection: status=%d inspections=%d error=%v", response.StatusCode, inspected.Load(), err)
			}
		})
	}
}
