// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"net/url"
	"testing"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return parsed
}

func newDefaultClassifier(t *testing.T) *Classifier {
	t.Helper()
	classifier, err := NewClassifier(ClassifierOptions{})
	if err != nil {
		t.Fatalf("NewClassifier() returned unexpected error: %v", err)
	}
	return classifier
}

// The URLs below were captured from npm, Yarn, pnpm and Bun traffic.
func TestClassify(t *testing.T) {
	const scopedPackument = "/@babel%2Fhelper-string-parser"
	tests := []struct {
		url           string
		kind          RequestKind
		name          string
		version       string
		packumentPath string
	}{
		{url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", kind: RequestTarball, name: "left-pad", version: "1.3.0", packumentPath: "/left-pad"},
		{url: "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.25.9.tgz", kind: RequestTarball, name: "@babel/helper-string-parser", version: "7.25.9", packumentPath: scopedPackument},
		{url: "https://registry.yarnpkg.com/@babel%2fhelper-string-parser/-/helper-string-parser-7.25.9.tgz", kind: RequestTarball, name: "@babel/helper-string-parser", version: "7.25.9", packumentPath: scopedPackument},
		{url: "https://registry.npmjs.org/@babel%2Fhelper-string-parser/-/helper-string-parser-7.25.9.tgz", kind: RequestTarball, name: "@babel/helper-string-parser", version: "7.25.9", packumentPath: scopedPackument},
		{url: "https://registry.npmjs.org/%40babel/helper-string-parser/-/helper-string-parser-7.25.9.tgz", kind: RequestTarball, name: "@babel/helper-string-parser", version: "7.25.9", packumentPath: scopedPackument},
		{url: "https://artifactory.example/api/npm/npm-remote/%40acme/utils/-/utils-1.0.0.tgz", kind: RequestTarball, name: "@acme/utils", version: "1.0.0", packumentPath: "/api/npm/npm-remote/@acme%2Futils"},
		{url: "https://registry.npmjs.org/express-session/-/express-session-1.18.1.tgz", kind: RequestTarball, name: "express-session", version: "1.18.1", packumentPath: "/express-session"},
		{url: "https://registry.npmjs.org/lib-2/-/lib-2-2.0.0-beta.1.tgz", kind: RequestTarball, name: "lib-2", version: "2.0.0-beta.1", packumentPath: "/lib-2"},
		{url: "https://registry.npmjs.org/JSONStream/-/JSONStream-1.3.5.tgz", kind: RequestTarball, name: "JSONStream", version: "1.3.5", packumentPath: "/JSONStream"},
		{url: "https://registry.npmjs.org/typescript/-/typescript-5.8.0-dev.20250101.tgz", kind: RequestTarball, name: "typescript", version: "5.8.0-dev.20250101", packumentPath: "/typescript"},
		{url: "https://registry.npmjs.org/pkg/-/pkg-1.0.0+build.1.tgz", kind: RequestTarball, name: "pkg", version: "1.0.0+build.1", packumentPath: "/pkg"},
		{url: "https://artifactory.example/artifactory/api/npm/npm-remote/left-pad/-/left-pad-1.3.0.tgz", kind: RequestTarball, name: "left-pad", version: "1.3.0", packumentPath: "/artifactory/api/npm/npm-remote/left-pad"},
		// GitLab names scoped tarballs after the full scoped name, literal or percent-encoded.
		{url: "https://gitlab.example/api/v4/projects/1/packages/npm/@scope/pkg/-/@scope/pkg-1.0.0.tgz", kind: RequestTarball, name: "@scope/pkg", version: "1.0.0", packumentPath: "/api/v4/projects/1/packages/npm/@scope%2Fpkg"},
		{url: "https://gitlab.example/api/v4/projects/1/packages/npm/@scope%2Fpkg/-/@scope%2Fpkg-1.0.0.tgz", kind: RequestTarball, name: "@scope/pkg", version: "1.0.0", packumentPath: "/api/v4/projects/1/packages/npm/@scope%2Fpkg"},
		{url: "https://gitlab.example/api/v4/projects/1/packages/npm/@scope/pkg/-/@other/pkg-1.0.0.tgz", kind: RequestUnrelated},
		// Tarballs are recognized on any host: an unknown host cannot opt out of evaluation.
		{url: "https://evil.example/left-pad/-/left-pad-1.3.0.tgz", kind: RequestTarball, name: "left-pad", version: "1.3.0", packumentPath: "/left-pad"},

		{url: "https://registry.npmjs.org/left-pad", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/@babel%2fhelper-string-parser", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/@babel%2Fhelper-string-parser", kind: RequestUnrelated},

		{url: "https://registry.npmjs.org/-/v1/search?text=x", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/v1/search?text=left-pad-1.3.0.tgz", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/ping", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/package/left-pad/dist-tags", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/v1/login", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/whoami", kind: RequestRegistryAPI},
		{url: "https://registry.npmjs.org/-/user/org.couchdb.user:alice", kind: RequestRegistryAPI},

		{url: "https://cdn.npmmirror.com/packages/left-pad/1.3.0/left-pad-1.3.0.tgz", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/left-pad/-/other-1.3.0.tgz", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.tgz", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/left-pad/-/left-pad-latest.tgz", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.zip", kind: RequestUnrelated},
		{url: "https://registry.npmjs.org/left-pad/-/sub/left-pad-1.3.0.tgz", kind: RequestUnrelated},
		{url: "ftp://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", kind: RequestUnrelated},
	}

	classifier := newDefaultClassifier(t)
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			kind, artifact := classifier.Classify(mustParseURL(t, tc.url))
			if kind != tc.kind {
				t.Fatalf("Classify(%q) kind = %v, want %v", tc.url, kind, tc.kind)
			}
			if tc.kind != RequestTarball {
				return
			}
			if artifact.Name != tc.name || artifact.Version != tc.version {
				t.Fatalf("Classify(%q) = %s@%s, want %s@%s", tc.url, artifact.Name, artifact.Version, tc.name, tc.version)
			}
			if got := artifact.PackumentURL.EscapedPath(); got != tc.packumentPath {
				t.Fatalf("Classify(%q) packument path = %q, want %q", tc.url, got, tc.packumentPath)
			}
			if artifact.PackumentURL.Host != mustParseURL(t, tc.url).Host {
				t.Fatalf("Classify(%q) packument host = %q, want the tarball's host", tc.url, artifact.PackumentURL.Host)
			}
		})
	}
}

func TestClassifyRedactsSource(t *testing.T) {
	kind, artifact := newDefaultClassifier(t).Classify(
		mustParseURL(t, "https://user:pw@registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz?token=secret#x"),
	)
	if kind != RequestTarball {
		t.Fatalf("kind = %v, want tarball", kind)
	}
	if want := "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"; artifact.Source != want {
		t.Fatalf("Source = %q, want %q", artifact.Source, want)
	}
	if artifact.PackumentURL.User != nil {
		t.Fatal("packument URL kept the tarball URL's user information")
	}
}

func TestClassifyConfiguredRegistry(t *testing.T) {
	classifier, err := NewClassifier(ClassifierOptions{RegistryURLs: []string{"http://127.0.0.1:4873/npm/"}})
	if err != nil {
		t.Fatalf("NewClassifier() returned unexpected error: %v", err)
	}

	kind, artifact := classifier.Classify(mustParseURL(t, "http://127.0.0.1:4873/npm/left-pad/-/left-pad-1.3.0.tgz"))
	if kind != RequestTarball {
		t.Fatalf("configured registry tarball: kind = %v, want tarball", kind)
	}
	if got := artifact.PackumentURL.String(); got != "http://127.0.0.1:4873/npm/left-pad" {
		t.Fatalf("packument URL = %q, want http://127.0.0.1:4873/npm/left-pad", got)
	}

	if kind, _ := classifier.Classify(mustParseURL(t, "http://127.0.0.1:4873/npm/-/ping")); kind != RequestRegistryAPI {
		t.Fatalf("configured registry ping: kind = %v, want registry API", kind)
	}
}

func TestClassifyPercentEncodedScopeUnderConfiguredPrefix(t *testing.T) {
	classifier, err := NewClassifier(ClassifierOptions{RegistryURLs: []string{"https://npm.corp/api/npm/remote"}})
	if err != nil {
		t.Fatalf("NewClassifier() returned unexpected error: %v", err)
	}

	kind, artifact := classifier.Classify(mustParseURL(t, "https://npm.corp/api/npm/remote/%40scope%2Fpkg/-/pkg-1.0.0.tgz"))
	if kind != RequestTarball || artifact.Name != "@scope/pkg" || artifact.Version != "1.0.0" {
		t.Fatalf("Classify() = %v %s@%s, want tarball @scope/pkg@1.0.0", kind, artifact.Name, artifact.Version)
	}
	if got := artifact.PackumentURL.EscapedPath(); got != "/api/npm/remote/@scope%2Fpkg" {
		t.Fatalf("packument path = %q, want /api/npm/remote/@scope%%2Fpkg", got)
	}
}

func TestNewClassifierRejectsInvalidRegistryURL(t *testing.T) {
	for _, raw := range []string{"not a url", "ftp://x/"} {
		if _, err := NewClassifier(ClassifierOptions{RegistryURLs: []string{raw}}); err == nil {
			t.Errorf("NewClassifier(%q) returned nil error, want an invalid registry URL error", raw)
		}
	}
}
