// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyHandlerDefersOpaqueTarballsToResponse(t *testing.T) {
	handler, evaluated := recordingHandler(t, nil)
	for _, raw := range []string{
		"https://codeload.github.com/acme/widget/tar.gz/0123abc",
		"https://npm.pkg.github.com/download/@acme/widget/1.2.3/abcdef",
		"https://example.com/widget.tgz",
	} {
		hook, err := handler.HandleRequest(context.Background(), getRequest(t, raw))
		if hook == nil || err != nil {
			t.Fatalf("%s: HandleRequest() = %v, %v; want a response hook", raw, hook != nil, err)
		}
	}
	if got := len(evaluated()); got != 0 {
		t.Fatalf("evaluations = %d, want none before the response", got)
	}
}

func TestProxyHandlerInspectsOpaqueTarballs(t *testing.T) {
	tarball := npmTarball(t, "gzip", tarEntry{name: "widget-0123abc/package.json", body: readNpmFixture(t, "manifest/widget.json")})
	var encoded bytes.Buffer
	encoder := gzip.NewWriter(&encoded)
	_, _ = encoder.Write(tarball)
	_ = encoder.Close()
	rawPrefix := append(bytes.Repeat([]byte{0x78}, 512), rawTar(rawTarEntry("package/package.json", '0', readNpmFixture(t, "manifest/widget.json")))...)
	capitalized := npmTarball(t, "gzip", tarEntry{name: "package/Package.json", body: readNpmFixture(t, "manifest/widget.json")})
	headers := npmTarball(t, "gzip", tarEntry{name: "node-v20.0.0/include/node/node.h", body: "#pragma once"})

	var fetches atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		switch r.URL.Path {
		case "/widget.tgz", "/blob/abc":
			_, _ = w.Write(tarball)
		case "/raw-prefix.tgz":
			_, _ = w.Write(rawPrefix)
		case "/capitalized.tgz":
			_, _ = w.Write(capitalized)
		case "/encoded.tgz":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(encoded.Bytes())
		case "/headers.tar.gz":
			_, _ = w.Write(headers)
		case "/corrupt.tgz":
			_, _ = w.Write(tarball[:len(tarball)-12])
		case "/huge.tgz":
			w.Header().Set("Content-Length", strconv.FormatInt(archive.MaxArtifactBytes+1, 10))
			w.WriteHeader(http.StatusOK)
		case "/created.tgz":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(tarball)
		case "/non-authoritative.tgz":
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = w.Write(tarball)
		case "/reset-content.tgz":
			w.WriteHeader(http.StatusResetContent)
			_, _ = w.Write(tarball)
		case "/multiple-choices.tgz":
			w.WriteHeader(http.StatusMultipleChoices)
			_, _ = w.Write(tarball)
		case "/html-redirect.tgz":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("<a href=\"/elsewhere\">Found</a>"))
		case "/no-content.tgz":
			w.WriteHeader(http.StatusNoContent)
		case "/upper.tgz":
			w.Header().Set("Location", "http://LOCALHOST:"+r.Host[strings.LastIndex(r.Host, ":")+1:]+"/blob/upper")
			w.WriteHeader(http.StatusFound)
		case "/dots.tgz":
			w.Header().Set("Location", "/hop/%2e%2e/blob/dots")
			w.WriteHeader(http.StatusFound)
		case "/backslash.tgz":
			w.Header().Set("Location", "/hop\\..\\blob/backslash")
			w.WriteHeader(http.StatusFound)
		case "/blob/upper", "/blob/dots", "/blob/backslash":
			_, _ = w.Write(tarball)
		case "/bad-location.tgz":
			w.Header().Set("Location", "http://[bad")
			w.WriteHeader(http.StatusFound)
		case "/encoded-host.tgz":
			// Node accepts a percent-encoded host; Go cannot parse it.
			w.Header().Set("Location", "http://%65xample.invalid/download")
			w.WriteHeader(http.StatusFound)
		case "/fragment.tgz":
			http.Redirect(w, r, "/blob/abc#download", http.StatusFound)
		case "/redirect.tgz":
			http.Redirect(w, r, "/blob/abc", http.StatusFound)
		case "/cached.tgz":
			if r.Header.Get("If-None-Match") != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write(tarball)
		}
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		path, source string
		block        bool
		status       int
		evaluations  int
		body         []byte
	}{
		{path: "/widget.tgz", source: "/widget.tgz", status: http.StatusOK, evaluations: 1, body: tarball},
		{path: "/widget.tgz", block: true, status: http.StatusForbidden, evaluations: 1},
		{path: "/raw-prefix.tgz", status: http.StatusBadGateway},
		{path: "/capitalized.tgz", block: true, status: http.StatusForbidden, evaluations: 1},
		{path: "/encoded.tgz", source: "/encoded.tgz", status: http.StatusOK, evaluations: 1, body: tarball},
		{path: "/headers.tar.gz", status: http.StatusOK, body: headers},
		{path: "/corrupt.tgz", status: http.StatusBadGateway},
		{path: "/huge.tgz", status: http.StatusBadGateway},
		{path: "/redirect.tgz", source: "/blob/abc", status: http.StatusOK, evaluations: 1, body: tarball},
		{path: "/created.tgz", block: true, status: http.StatusForbidden, evaluations: 1},
		{path: "/non-authoritative.tgz", block: true, status: http.StatusForbidden, evaluations: 1},
		{path: "/reset-content.tgz", block: true, status: http.StatusForbidden, evaluations: 1},
		{path: "/multiple-choices.tgz", block: true, status: http.StatusForbidden, evaluations: 1},
		{path: "/no-content.tgz", block: true, status: http.StatusNoContent, body: []byte{}},
		{path: "/fragment.tgz", source: "/blob/abc", status: http.StatusOK, evaluations: 1, body: tarball},
	} {
		t.Run(tc.path, func(t *testing.T) {
			var result error
			if tc.block {
				result = errors.New("blocked by policy")
			}
			handler, evaluated := recordingHandler(t, result)
			response, err := proxiedClient(t, handler.HandleRequest).Get(upstream.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			artifacts := evaluated()
			if response.StatusCode != tc.status || len(artifacts) != tc.evaluations || (tc.body != nil && !bytes.Equal(body, tc.body)) {
				t.Fatalf("status=%d evaluations=%d body-match=%v, want %d, %d and the upstream bytes",
					response.StatusCode, len(artifacts), bytes.Equal(body, tc.body), tc.status, tc.evaluations)
			}
			if tc.source != "" && (artifacts[0].Name != "@acme/widget" || artifacts[0].Version != "1.2.3" || artifacts[0].Source != upstream.URL+tc.source) {
				t.Fatalf("evaluated %+v, want @acme/widget@1.2.3 from %s", artifacts[0], tc.source)
			}
		})
	}

	// Node follows a Location after WHATWG URL normalization, so the target is
	// requested in a form the Location does not spell out.
	for redirect, followed := range map[string]string{
		"/upper.tgz":     strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1) + "/blob/upper",
		"/dots.tgz":      upstream.URL + "/blob/dots",
		"/backslash.tgz": upstream.URL + "/blob/backslash",
	} {
		t.Run("normalized "+redirect, func(t *testing.T) {
			handler, evaluated := recordingHandler(t, errors.New("blocked by policy"))
			client := proxiedClient(t, handler.HandleRequest)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			var response *http.Response
			for _, target := range []string{upstream.URL + redirect, followed} {
				var err error
				if response, err = client.Get(target); err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
			}
			if response.StatusCode != http.StatusForbidden || len(evaluated()) != 1 {
				t.Fatalf("status=%d evaluations=%d, want the normalized redirect target inspected and blocked", response.StatusCode, len(evaluated()))
			}
		})
	}

	t.Run("unparsable location", func(t *testing.T) {
		handler, evaluated := recordingHandler(t, errors.New("must not be evaluated"))
		// The transport skips the client's own Location parsing.
		transport := proxiedClient(t, handler.HandleRequest).Transport
		for _, path := range []string{"/encoded-host.tgz", "/bad-location.tgz"} {
			request, err := http.NewRequest(http.MethodGet, upstream.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") == "" || len(evaluated()) != 0 {
				t.Fatalf("%s: status=%d evaluations=%d, want the 302 passed through untracked", path, response.StatusCode, len(evaluated()))
			}
		}
	})

	t.Run("redirect body", func(t *testing.T) {
		handler, evaluated := recordingHandler(t, errors.New("must not be evaluated"))
		client := proxiedClient(t, handler.HandleRequest)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := client.Get(upstream.URL + "/html-redirect.tgz")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusFound || !bytes.Contains(body, []byte("Found")) || len(evaluated()) != 0 {
			t.Fatalf("status=%d body=%q evaluations=%d, want the 302 and its HTML body forwarded unevaluated", response.StatusCode, body, len(evaluated()))
		}
	})

	t.Run("not modified", func(t *testing.T) {
		handler, evaluated := recordingHandler(t, nil)
		handler.Client = upstream.Client()
		request, _ := http.NewRequest(http.MethodGet, upstream.URL+"/cached.tgz", nil)
		request.Header.Set("If-None-Match", `"cached"`)
		before := fetches.Load()
		response, err := proxiedClient(t, handler.HandleRequest).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotModified || len(evaluated()) != 1 || fetches.Load()-before != 2 {
			t.Fatalf("status=%d evaluations=%d fetches=%d, want 304 after one full re-fetch evaluated once",
				response.StatusCode, len(evaluated()), fetches.Load()-before)
		}
	})
}

func TestProxyHandlerInspectsDownloadsFromResponse(t *testing.T) {
	tarball := npmTarball(t, "gzip", tarEntry{name: "widget-0123abc/package.json", body: readNpmFixture(t, "manifest/widget.json")})
	var fetches atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		switch r.URL.Path {
		case "/octet":
			w.Header().Set("Content-Type", "application/octet-stream")
		case "/binary":
			w.Header().Set("Content-Type", "binary/octet-stream")
		case "/untyped":
			w.Header()["Content-Type"] = nil
		case "/untyped-unbounded":
			w.Header()["Content-Type"] = nil
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		case "/json":
			w.Header().Set("Content-Type", "application/json")
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
		case "/repos/acme/widget/tarball/v1":
			// GitHub's API tarball endpoint redirects to a codeload legacy.tar.gz.
			http.Redirect(w, r, "/acme/widget/legacy.tar.gz/refs/tags/v1", http.StatusFound)
			return
		case "/acme/widget/legacy.tar.gz/refs/tags/v1":
			w.Header().Set("Content-Type", "application/x-gzip")
		case "/download/@acme/widget/1.2.3/abc":
			// GitHub Packages redirects downloads to a blob store; its media
			// type is assumed to be application/octet-stream.
			http.Redirect(w, r, "/npm/blobs/sha256:abc", http.StatusFound)
			return
		case "/npm/blobs/sha256:abc":
			w.Header().Set("Content-Type", "application/octet-stream")
		case "/moved":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Location", "/octet")
			w.WriteHeader(http.StatusFound)
		case "/partial":
			w.Header().Set("Content-Type", "application/octet-stream")
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Range", "bytes 0-9/"+strconv.Itoa(len(tarball)))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(tarball[:10])
				return
			}
		}
		_, _ = w.Write(tarball)
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		path, source string
		status       int
		header       string
		noFollow     bool
		fetches      int32
	}{
		{path: "/octet", status: http.StatusForbidden},
		{path: "/binary", status: http.StatusForbidden},
		{path: "/untyped", status: http.StatusForbidden},
		{path: "/untyped-unbounded", status: http.StatusOK},
		{path: "/json", status: http.StatusOK},
		{path: "/text", status: http.StatusOK},
		{path: "/repos/acme/widget/tarball/v1", source: "/acme/widget/legacy.tar.gz/refs/tags/v1", status: http.StatusForbidden},
		{path: "/download/@acme/widget/1.2.3/abc", source: "/npm/blobs/sha256:abc", status: http.StatusForbidden},
		{path: "/moved", status: http.StatusFound, noFollow: true},
		{path: "/partial", source: "/partial", status: http.StatusForbidden, header: "Range", fetches: 2},
	} {
		t.Run(tc.path, func(t *testing.T) {
			handler, evaluated := recordingHandler(t, errors.New("blocked by policy"))
			handler.Client = upstream.Client()
			client := proxiedClient(t, handler.HandleRequest)
			if tc.noFollow {
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			}
			request, _ := http.NewRequest(http.MethodGet, upstream.URL+tc.path, nil)
			if tc.header != "" {
				request.Header.Set(tc.header, "bytes=0-9")
			}
			before := fetches.Load()
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			artifacts := evaluated()
			wantEvaluations := 0
			if tc.status == http.StatusForbidden {
				wantEvaluations = 1
			}
			if response.StatusCode != tc.status || len(artifacts) != wantEvaluations {
				t.Fatalf("status=%d evaluations=%d, want %d and %d", response.StatusCode, len(artifacts), tc.status, wantEvaluations)
			}
			if tc.source != "" && artifacts[0].Source != upstream.URL+tc.source {
				t.Fatalf("source = %s, want %s", artifacts[0].Source, upstream.URL+tc.source)
			}
			if tc.fetches != 0 && fetches.Load()-before != tc.fetches {
				t.Fatalf("fetches = %d, want %d", fetches.Load()-before, tc.fetches)
			}
		})
	}

	// Go's server drops Content-Type from a 304, so build the responses directly.
	octet := http.Header{"Content-Type": {"application/octet-stream"}}
	t.Run("not modified", func(t *testing.T) {
		handler, evaluated := recordingHandler(t, errors.New("blocked by policy"))
		handler.Client = upstream.Client()
		request := getRequest(t, upstream.URL+"/octet")
		request.Header.Set("If-None-Match", `"cached"`)
		hook, err := handler.observeDownload(context.Background(), proxy.Response{Request: request, StatusCode: http.StatusNotModified, Header: octet})
		if hook != nil || !errors.Is(err, proxy.ErrResponseRejected) || len(evaluated()) != 1 {
			t.Fatalf("observeDownload() = %v, %v with %d evaluations; want the re-fetched archive rejected", hook != nil, err, len(evaluated()))
		}
	})
	t.Run("declared length over limit", func(t *testing.T) {
		handler, _ := recordingHandler(t, errors.New("must not be evaluated"))
		header := octet.Clone()
		header.Set("Content-Length", strconv.FormatInt(archive.MaxArtifactBytes+1, 10))
		hook, err := handler.observeDownload(context.Background(), proxy.Response{Request: getRequest(t, upstream.URL+"/octet"), StatusCode: http.StatusOK, Header: header})
		if hook != nil || err != nil {
			t.Fatalf("observeDownload() = %v, %v; want the oversized download passed untouched", hook != nil, err)
		}
	})
}

func TestProxyHandlerVerifiesTarballIdentityOnUnknownHosts(t *testing.T) {
	manifest := func(name, version string) string {
		return `{"name": "` + name + `", "version": "` + version + `"}`
	}
	matching := npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: manifest("left-pad", "1.3.0")})
	otherName := npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: manifest("evil", "1.3.0")})
	otherVersion := npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: manifest("left-pad", "9.9.9")})
	tarballs := map[string][]byte{"match": matching, "name": otherName, "version": otherVersion}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		variant := r.URL.Query().Get("v")
		switch {
		case r.URL.Query().Get("status") != "":
			status, _ := strconv.Atoi(r.URL.Query().Get("status"))
			if r.URL.Query().Has("location") {
				// npm does not follow a 300, so its body is installed.
				w.Header().Set("Location", "/blob")
			}
			w.WriteHeader(status)
			_, _ = w.Write(tarballs[variant])
		case variant == "redirect":
			http.Redirect(w, r, "/blob", http.StatusFound)
		case r.URL.Path == "/blob":
			_, _ = w.Write(otherName)
		case variant == "text":
			_, _ = w.Write([]byte("not a tarball"))
		case variant == "huge":
			w.Header().Set("Content-Length", strconv.FormatInt(archive.MaxArtifactBytes+1, 10))
			w.WriteHeader(http.StatusOK)
		case r.Header.Get("Range") != "":
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(tarballs[variant][:10])
		case r.Header.Get("If-None-Match") != "":
			w.WriteHeader(http.StatusNotModified)
		default:
			_, _ = w.Write(tarballs[variant])
		}
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		name, variant, header string
		client                bool
		serve, status         int
	}{
		{name: "300 mismatch", variant: "name", serve: 300, status: http.StatusForbidden},
		{name: "302 without location mismatch", variant: "name", serve: 302, status: http.StatusForbidden},
		{name: "307 without location mismatch", variant: "version", serve: 307, status: http.StatusForbidden},
		{name: "300 match", variant: "match", serve: 300, status: 300},
		{name: "300 with location match", variant: "match&location", serve: 300, status: 300},
		{name: "300 with location mismatch", variant: "name&location", serve: 300, status: http.StatusForbidden},
		{name: "302 without location match", variant: "match", serve: 302, status: 302},
		{name: "307 without location match", variant: "match", serve: 307, status: 307},
		{name: "match", variant: "match", status: http.StatusOK},
		{name: "other name", variant: "name", status: http.StatusForbidden},
		{name: "other version", variant: "version", status: http.StatusForbidden},
		{name: "not an archive", variant: "text", status: http.StatusBadGateway},
		{name: "oversized", variant: "huge", status: http.StatusBadGateway},
		{name: "redirect to other package", variant: "redirect", client: true, status: http.StatusForbidden},
		{name: "partial match", variant: "match", header: "Range", client: true, status: http.StatusPartialContent},
		{name: "partial mismatch", variant: "name", header: "Range", client: true, status: http.StatusForbidden},
		{name: "partial without client", variant: "match", header: "Range", status: http.StatusBadGateway},
		{name: "cached match", variant: "match", header: "If-None-Match", client: true, status: http.StatusNotModified},
		{name: "cached mismatch", variant: "version", header: "If-None-Match", client: true, status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, evaluated := recordingHandler(t, nil)
			if tc.client {
				handler.Client = upstream.Client()
			}
			client := proxiedClient(t, handler.HandleRequest)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			request, err := http.NewRequest(http.MethodGet, upstream.URL+"/left-pad/-/left-pad-1.3.0.tgz?v="+tc.variant+"&status="+map[bool]string{true: strconv.Itoa(tc.serve)}[tc.serve != 0], nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.header != "" {
				request.Header.Set(tc.header, "bytes=0-9")
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			artifacts := evaluated()
			if response.StatusCode != tc.status || len(artifacts) != 1 || artifacts[0].Name != "left-pad" || artifacts[0].Version != "1.3.0" {
				t.Fatalf("status=%d evaluations=%+v, want %d after evaluating only left-pad@1.3.0", response.StatusCode, artifacts, tc.status)
			}
		})
	}
}

func TestProxyHandlerRefetchSendsNoReferer(t *testing.T) {
	tarball := npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: `{"name": "left-pad", "version": "1.3.0"}`})
	var referers, credentials atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "" {
			referers.Add(1)
		}
		if r.Header.Get("X-Private-Token") != "" || r.Header.Get("X-Api-Key") != "" || r.Header.Get("Authorization") != "" {
			credentials.Add(1)
		}
		_, _ = w.Write(tarball)
	}))
	defer destination.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(tarball[:10])
			return
		}
		http.Redirect(w, r, destination.URL+"/blob", http.StatusFound)
	}))
	defer upstream.Close()
	handler, _ := recordingHandler(t, nil)
	handler.Client = upstream.Client()
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/left-pad/-/left-pad-1.3.0.tgz?token=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Range", "bytes=0-9")
	request.Header.Set("X-Private-Token", "secret")
	request.Header.Set("X-Api-Key", "secret")
	request.Header.Set("Authorization", "Bearer secret")
	response, err := proxiedClient(t, handler.HandleRequest).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusPartialContent || referers.Load() != 0 || credentials.Load() != 0 {
		t.Fatalf("status=%d requests with Referer=%d with credentials=%d, want 206 and none", response.StatusCode, referers.Load(), credentials.Load())
	}
}
