// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
)

func TestUVArchiveSelectionUsesOriginalExtension(t *testing.T) {
	for _, test := range []struct {
		filename string
		want     pypi.ArchiveFormat
	}{
		{"download.tar.gz", pypi.ArchiveGzip}, {"download.tgz", pypi.ArchiveGzip},
		{"download.tar.zst", pypi.ArchiveZstandard}, {"download.zip", pypi.ArchiveZIP},
		{"project-1.0-py3-none-any.whl", pypi.ArchiveZIP}, {"download.tar", pypi.ArchiveTAR},
		{"download.tar.xz", pypi.ArchiveXZ}, {"download.tar.bz2", pypi.ArchiveBzip2},
		{"download.tar.lzma", pypi.ArchiveLZMA}, {"download.tar.lz", pypi.ArchiveUnsupported},
		{"download", pypi.ArchiveUnknown},
	} {
		t.Run(test.filename, func(t *testing.T) {
			source, _ := url.Parse("https://source.example/" + test.filename + "?token=secret")
			target, _ := url.Parse("https://cdn.example/contradiction.zip")
			format, err := selectArchive(pypi.ArchiveInput{URL: *source, ResponseURL: *target,
				Header: http.Header{"Content-Type": {"application/zip"}, "Content-Disposition": {`attachment; filename="other.zip"`}},
				Probe: func() (pypi.ArchiveSignatures, error) {
					t.Fatal("uv must select from its source extension")
					return pypi.ArchiveSignatures{}, nil
				},
			})
			if err != nil || format != test.want {
				t.Fatalf("format=%v err=%v, want %v", format, err, test.want)
			}
		})
	}
}

func TestUVArchiveSelectionUsesAdvertisedFilename(t *testing.T) {
	source, _ := url.Parse("https://source.example/opaque")
	format, err := selectArchive(pypi.ArchiveInput{URL: *source, RegistryFilename: "project-1.0.tar.gz"})
	if err != nil || format != pypi.ArchiveGzip {
		t.Fatalf("advertised archive format=%v err=%v", format, err)
	}
}
