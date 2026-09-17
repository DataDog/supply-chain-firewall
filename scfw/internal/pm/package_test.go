// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
)

func TestPackageMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		pkg  Package
		want string
	}{
		{
			name: "zero PublishDate is omitted",
			pkg: Package{
				Ecosystem: ecosystem.PYPI,
				Name:      "six",
				Version:   "1.16.0",
				Source:    "https://example.com",
			},
			want: `{"ecosystem":"PyPI","package_name":"six","package_version":"1.16.0","package_source":"https://example.com"}`,
		},
		{
			name: "empty Source is omitted",
			pkg: Package{
				Ecosystem: ecosystem.NPM,
				Name:      "lodash",
				Version:   "4.17.21",
			},
			want: `{"ecosystem":"npm","package_name":"lodash","package_version":"4.17.21"}`,
		},
		{
			name: "non-zero PublishDate is included",
			pkg: Package{
				Ecosystem:   ecosystem.PYPI,
				Name:        "six",
				Version:     "1.16.0",
				PublishDate: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			want: `{"ecosystem":"PyPI","package_name":"six","package_version":"1.16.0","publish_date":"2024-01-02T03:04:05Z"}`,
		},
		{
			name: "Source and PublishDate both included",
			pkg: Package{
				Ecosystem:   ecosystem.PYPI,
				Name:        "six",
				Version:     "1.16.0",
				Source:      "https://example.com",
				PublishDate: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			want: `{"ecosystem":"PyPI","package_name":"six","package_version":"1.16.0","package_source":"https://example.com","publish_date":"2024-01-02T03:04:05Z"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.pkg)
			if err != nil {
				t.Fatalf("json.Marshal(%+v) returned unexpected error: %v", tc.pkg, err)
			}
			if string(got) != tc.want {
				t.Fatalf("json.Marshal(%+v) = %s, want %s", tc.pkg, got, tc.want)
			}
		})
	}
}
