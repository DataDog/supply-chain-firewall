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
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
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
	headers := npmTarball(t, "gzip", tarEntry{name: "node-v20.0.0/include/node/node.h", body: "#pragma once"})

	var fetches atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		switch r.URL.Path {
		case "/widget.tgz", "/blob/abc":
			_, _ = w.Write(tarball)
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
		{path: "/encoded.tgz", source: "/encoded.tgz", status: http.StatusOK, evaluations: 1, body: tarball},
		{path: "/headers.tar.gz", status: http.StatusOK, body: headers},
		{path: "/corrupt.tgz", status: http.StatusBadGateway},
		{path: "/huge.tgz", status: http.StatusBadGateway},
		{path: "/redirect.tgz", source: "/blob/abc", status: http.StatusOK, evaluations: 1, body: tarball},
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
