// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"testing"
	"time"
)

func TestIsNpmRegistrySource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "registry.npmjs.org", source: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", want: true},
		{name: "http scheme", source: "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", want: true},
		{name: "scoped package", source: "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", want: true},
		{name: "unrelated domain", source: "https://example.com/left-pad-1.3.0.tgz", want: false},
		{name: "unsupported scheme", source: "ftp://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", want: false},
		{name: "malformed URL", source: "not a url", want: false},
		{name: "empty string", source: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNpmRegistrySource(tc.source); got != tc.want {
				t.Fatalf("isNpmRegistrySource(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

func TestParseNpmPackageMetadata(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		version string
		wantErr bool
		want    time.Time
	}{
		{
			name:    "publish timestamp present",
			body:    `{"time": {"1.3.0": "2016-04-25T18:56:20.452Z"}}`,
			version: "1.3.0",
			want:    time.Date(2016, 4, 25, 18, 56, 20, 452000000, time.UTC),
		},
		{
			name:    "missing version",
			body:    `{"time": {"1.3.0": "2016-04-25T18:56:20.452Z"}}`,
			version: "9.9.9",
			wantErr: true,
		},
		{
			name:    "empty timestamp",
			body:    `{"time": {"1.3.0": ""}}`,
			version: "1.3.0",
			wantErr: true,
		},
		{
			name:    "malformed timestamp",
			body:    `{"time": {"1.3.0": "not a timestamp"}}`,
			version: "1.3.0",
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			body:    `not json`,
			version: "1.3.0",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNpmPackageMetadata([]byte(tc.body), "left-pad", tc.version)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseNpmPackageMetadata(%q, %q) = %v, want error", tc.body, tc.version, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNpmPackageMetadata(%q, %q) returned unexpected error: %v", tc.body, tc.version, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parseNpmPackageMetadata(%q, %q) = %v, want %v", tc.body, tc.version, got, tc.want)
			}
		})
	}
}

func TestResolveNpmPublishDate_NonRegistrySourceIsNoop(t *testing.T) {
	got, err := resolveNpmPublishDate(context.Background(), "left-pad", "1.3.0", "https://example.com/left-pad-1.3.0.tgz")
	if err != nil {
		t.Fatalf("resolveNpmPublishDate() returned unexpected error: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("resolveNpmPublishDate() = %v, want zero time", got)
	}
}

func TestResolveNpmPublishDate_RealNpm(t *testing.T) {
	const (
		name    = "axios"
		version = "1.7.0"
	)
	want := time.Date(2024, 5, 19, 20, 25, 3, 615000000, time.UTC)

	tests := []struct {
		name   string
		source string
	}{
		{name: "empty source", source: ""},
		{name: "registry.npmjs.org source", source: "https://registry.npmjs.org/axios/-/axios-1.7.0.tgz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			got, err := resolveNpmPublishDate(ctx, name, version, tc.source)
			if err != nil {
				t.Fatalf("resolveNpmPublishDate(%q, %q, %q) returned unexpected error: %v", name, version, tc.source, err)
			}
			if !got.Equal(want) {
				t.Fatalf("resolveNpmPublishDate(%q, %q, %q) = %v, want %v", name, version, tc.source, got, want)
			}
		})
	}
}

func TestResolveNpmPublishDate_RealNpm_NonexistentPackage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const name = "this-package-definitely-does-not-exist-xyz"

	got, err := resolveNpmPublishDate(ctx, name, "1.0.0", "")
	if err == nil {
		t.Fatalf("resolveNpmPublishDate(%q, ...) = %v, want error", name, got)
	}
}
