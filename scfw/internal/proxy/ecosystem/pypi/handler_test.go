// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestRewriteSimpleIndexResponses(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{
			name:        "PEP 503 HTML",
			contentType: "text/html; charset=utf-8",
			body:        `<a href="../../files/pkg-1.0.tar.gz#sha256=abc">pkg</a>`,
			want:        `href="proxy:https://index.example/files/pkg-1.0.tar.gz#sha256=abc"`,
		},
		{
			name:        "PEP 691 JSON",
			contentType: "application/vnd.pypi.simple.v1+json",
			body:        `{"files":[{"filename":"pkg.whl","url":"../../files/pkg.whl"}]}`,
			want:        `"url":"proxy:https://index.example/files/pkg.whl"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestURL, _ := url.Parse("https://index.example/simple/pkg/")
			response := &http.Response{
				Header:        http.Header{"Content-Type": []string{test.contentType}},
				Body:          io.NopCloser(strings.NewReader(test.body)),
				ContentLength: int64(len(test.body)),
				Request:       &http.Request{URL: requestURL},
			}
			err := (Handler{}).RewriteResponse(response, func(value *url.URL, _ *pm.Package) string { return "proxy:" + value.String() }, nil)
			if err != nil {
				t.Fatalf("RewriteResponse() error = %v", err)
			}
			body, _ := io.ReadAll(response.Body)
			if !strings.Contains(string(body), test.want) {
				t.Errorf("rewritten body = %q, want substring %q", body, test.want)
			}
		})
	}
}

func TestPackageFromDistributionURL(t *testing.T) {
	tests := []struct {
		url     string
		name    string
		version string
	}{
		{"https://files.example/my_pkg-1.2.3-py3-none-any.whl", "my-pkg", "1.2.3"},
		{"https://files.example/my-pkg-1.2.3.tar.gz", "my-pkg", "1.2.3"},
	}
	for _, test := range tests {
		destination, _ := url.Parse(test.url)
		pkg, ok := (Handler{}).Package(destination)
		if !ok || pkg.Name != test.name || pkg.Version != test.version {
			t.Errorf("Package(%q) = %+v, %t", test.url, pkg, ok)
		}
	}
}

func TestRewriteHTMLUsesAnchorFilenameAndDecodesEntities(t *testing.T) {
	requestURL, _ := url.Parse("https://index.example/simple/pkg/")
	body := `<a href="https://download.example/opaque?a=1&amp;b=2">my_pkg-1.2.3-py3-none-any.whl</a>`
	response := &http.Response{
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       &http.Request{URL: requestURL},
	}
	var gotURL string
	var gotPackage *pm.Package
	err := (Handler{}).RewriteResponse(response, func(value *url.URL, pkg *pm.Package) string {
		gotURL = value.String()
		gotPackage = pkg
		return "http://proxy/download/my_pkg-1.2.3-py3-none-any.whl"
	}, nil)
	if err != nil {
		t.Fatalf("RewriteResponse() error = %v", err)
	}
	if gotURL != "https://download.example/opaque?a=1&b=2" {
		t.Errorf("decoded URL = %q", gotURL)
	}
	if gotPackage == nil || gotPackage.Name != "my-pkg" || gotPackage.Version != "1.2.3" {
		t.Errorf("identified package = %+v", gotPackage)
	}
}
