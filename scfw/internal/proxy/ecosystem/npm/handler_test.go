// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestPackageFromTarballURL(t *testing.T) {
	destination, _ := url.Parse("https://registry.example/@scope/pkg/-/pkg-1.2.3.tgz")
	pkg, ok := (Handler{}).Package(destination)
	if !ok {
		t.Fatal("Package() did not recognize npm tarball")
	}
	if pkg.Name != "@scope/pkg" || pkg.Version != "1.2.3" {
		t.Errorf("Package() = %+v", pkg)
	}
}

func TestRewriteRequestRequestsFullPackument(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://registry.example/pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8")
	request.Header.Set("If-None-Match", `"abbreviated"`)
	registry, _ := url.Parse("https://registry.example/")
	(Handler{}).RewriteRequest(request, []*url.URL{registry})
	if got := request.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want full packument", got)
	}
	if got := request.Header.Get("If-None-Match"); got != "" {
		t.Errorf("If-None-Match = %q, want cleared after representation change", got)
	}
}

func TestRewriteRequestLeavesUnrecognizedTrafficUnchanged(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://artifacts.example/file.tgz", nil)
	if err != nil {
		t.Fatal(err)
	}
	const accept = "text/plain, application/vnd.npm.install-v1+json"
	request.Header.Set("Accept", accept)
	registry, _ := url.Parse("https://registry.example/")
	(Handler{}).RewriteRequest(request, []*url.URL{registry})
	if got := request.Header.Get("Accept"); got != accept {
		t.Errorf("Accept = %q, want %q", got, accept)
	}
}

func TestRewriteRequestPreservesOtherAcceptAlternatives(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://registry.example/@scope/pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/plain; q=0.2, application/vnd.npm.install-v1+json")
	registry, _ := url.Parse("https://registry.example/")
	(Handler{}).RewriteRequest(request, []*url.URL{registry})
	if got := request.Header.Get("Accept"); got != "application/json, text/plain; q=0.2" {
		t.Errorf("Accept = %q", got)
	}
}

func TestRewritePackumentCarriesPublishDate(t *testing.T) {
	const body = `{"name":"private-pkg","time":{"7.8.9":"2025-02-03T04:05:06.123Z"},"versions":{"7.8.9":{"dist":{"tarball":"https://artifacts.example/opaque"}}}}`
	requestURL, _ := url.Parse("https://registry.example/private-pkg")
	response := &http.Response{
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       &http.Request{URL: requestURL},
	}
	var identified *pm.Package
	err := (Handler{}).RewriteResponse(response, func(value *url.URL, pkg *pm.Package) string {
		if pkg != nil {
			copy := *pkg
			identified = &copy
		}
		return "proxy:" + value.String()
	}, nil)
	if err != nil {
		t.Fatalf("RewriteResponse() error = %v", err)
	}
	want := time.Date(2025, 2, 3, 4, 5, 6, 123000000, time.UTC)
	if identified == nil || identified.Name != "private-pkg" || identified.Version != "7.8.9" || !identified.PublishDate.Equal(want) {
		t.Errorf("identified package = %+v, want publish date %s", identified, want)
	}
}

func TestRewriteOversizedForcedPackumentFailsClosed(t *testing.T) {
	requestURL, _ := url.Parse("https://registry.example/private-pkg")
	request := &http.Request{Method: http.MethodGet, URL: requestURL, Header: make(http.Header)}
	request.Header.Set("Accept", "application/json")
	registry, _ := url.Parse("https://registry.example/")
	(Handler{}).RewriteRequest(request, []*url.URL{registry})
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: maxRewriteSize + 1,
		Request:       request,
	}
	if err := (Handler{}).RewriteResponse(response, func(value *url.URL, _ *pm.Package) string {
		return value.String()
	}, []*url.URL{registry}); err == nil {
		t.Fatal("RewriteResponse() error = nil, want oversized forced packument rejected")
	}
}

func TestRewriteMislabeledPackument(t *testing.T) {
	requestURL, _ := url.Parse("https://registry.example/private-pkg")
	request := &http.Request{Method: http.MethodGet, URL: requestURL, Header: make(http.Header)}
	request.Header.Set("Accept", "application/json")
	registry, _ := url.Parse("https://registry.example/")
	(Handler{}).RewriteRequest(request, []*url.URL{registry})
	const body = `{"name":"private-pkg","versions":{"1.0.0":{"dist":{"tarball":"https://artifacts.example/opaque"}}}}`
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
	rewritten := false
	if err := (Handler{}).RewriteResponse(response, func(value *url.URL, _ *pm.Package) string {
		rewritten = true
		return "proxy:" + value.String()
	}, []*url.URL{registry}); err != nil {
		t.Fatalf("RewriteResponse() error = %v", err)
	}
	if !rewritten {
		t.Fatal("RewriteResponse() did not rewrite mislabeled packument")
	}
}
