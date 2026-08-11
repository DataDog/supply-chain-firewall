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
			got, err := parsePyPIReleaseMetadata([]byte(tc.body), "six", tc.version)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePyPIReleaseMetadata(%q, %q) = %v, want error", tc.body, tc.version, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePyPIReleaseMetadata(%q, %q) returned unexpected error: %v", tc.body, tc.version, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parsePyPIReleaseMetadata(%q, %q) = %v, want %v", tc.body, tc.version, got, tc.want)
			}
		})
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
