// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestPipArchiveSelectionVersions(t *testing.T) {
	for _, version := range []pm.Version{{Major: 25, Minor: 3}, {Major: 26}, {Major: 26, Minor: 1}, {Major: 26, Minor: 2, Patch: 2}} {
		modern := !version.LessThan(pm.Version{Major: 26, Minor: 1})
		for _, test := range []struct {
			name, filename, contentType, disposition string
			signatures                               pypi.ArchiveSignatures
			legacy, current                          pypi.ArchiveFormat
			invalid                                  bool
		}{
			{name: "gzip and ZIP", filename: "download.tar.gz", signatures: pypi.ArchiveSignatures{ZIP: true, TAR: pypi.ArchiveGzip}, legacy: pypi.ArchiveZIP, current: pypi.ArchiveGzip},
			{name: "zstd and ZIP", filename: "download.zip", signatures: pypi.ArchiveSignatures{ZIP: true, TAR: pypi.ArchiveZstandard}, legacy: pypi.ArchiveZIP, current: pypi.ArchiveZIP},
			{name: "MIME before extension", filename: "download.zip", contentType: "application/x-gzip", signatures: pypi.ArchiveSignatures{ZIP: true, TAR: pypi.ArchiveGzip}, legacy: pypi.ArchiveZIP, current: pypi.ArchiveGzip},
			{name: "ZIP MIME", filename: "download.tar.gz", contentType: "application/zip", legacy: pypi.ArchiveZIP, current: pypi.ArchiveZIP},
			{name: "disposition", filename: "download.tar.gz", disposition: `attachment; filename="download.zip"`, legacy: pypi.ArchiveZIP, current: pypi.ArchiveZIP},
			{name: "disposition TAR", filename: "download.zip", disposition: `attachment; filename="download.tar.gz"`, legacy: pypi.ArchiveGzip, current: pypi.ArchiveGzip},
			{name: "opaque ZIP", filename: "download", contentType: "application/octet-stream", signatures: pypi.ArchiveSignatures{ZIP: true}, legacy: pypi.ArchiveZIP, current: pypi.ArchiveZIP},
			{name: "opaque gzip", filename: "download", contentType: "application/octet-stream", signatures: pypi.ArchiveSignatures{TAR: pypi.ArchiveGzip}, legacy: pypi.ArchiveGzip, current: pypi.ArchiveGzip},
			{name: "opaque ambiguous", filename: "download", signatures: pypi.ArchiveSignatures{ZIP: true, TAR: pypi.ArchiveGzip}, legacy: pypi.ArchiveZIP, current: pypi.ArchiveUnknown, invalid: true},
			{name: "uncompressed TAR", filename: "download.tar", legacy: pypi.ArchiveTAR, current: pypi.ArchiveTAR},
			{name: "bzip2", filename: "download.tbz", legacy: pypi.ArchiveBzip2, current: pypi.ArchiveBzip2},
			{name: "xz", filename: "download.tar.xz", signatures: pypi.ArchiveSignatures{TAR: pypi.ArchiveXZ}, legacy: pypi.ArchiveXZ, current: pypi.ArchiveXZ},
			{name: "legacy lzma", filename: "download.tlz", signatures: pypi.ArchiveSignatures{TAR: pypi.ArchiveLZMA}, legacy: pypi.ArchiveLZMA, current: pypi.ArchiveLZMA},
		} {
			t.Run(version.String()+"/"+test.name, func(t *testing.T) {
				source, _ := url.Parse("https://source.example/" + test.filename)
				manager := Pip{version: version}
				input := pypi.ArchiveInput{URL: *source, ResponseURL: *source, Header: http.Header{"Content-Type": {test.contentType}, "Content-Disposition": {test.disposition}}, Probe: func() (pypi.ArchiveSignatures, error) { return test.signatures, nil }}
				got, err := manager.selectArchive(input)
				want := test.legacy
				if modern {
					want = test.current
				}
				if (err != nil) != (modern && test.invalid) || got != want {
					t.Fatalf("format=%v err=%v, want %v", got, err, want)
				}
			})
		}
	}
}

func TestPipArchiveFilenameAndFailureHandling(t *testing.T) {
	source, _ := url.Parse("https://source.example/download")
	target, _ := url.Parse("https://cdn.example/archive.tar.gz")
	input := pypi.ArchiveInput{URL: *source, ResponseURL: *target, Header: make(http.Header), Probe: func() (pypi.ArchiveSignatures, error) { return pypi.ArchiveSignatures{}, nil }}
	for _, test := range []struct{ contentType, want string }{{"", "download.gz"}, {"application/zip", "download.zip"}, {"application/octet-stream", "download.bin"}} {
		input.Header.Set("Content-Type", test.contentType)
		got, err := pipDownloadFilename(input)
		if err != nil || got != test.want {
			t.Fatalf("filename=%q, err=%v, want %q", got, err, test.want)
		}
	}
	input.Header.Set("Content-Type", "application/unknown-host-mapping")
	if _, err := pipDownloadFilename(input); err == nil {
		t.Fatal("guessed an unknown MIME extension across a redirect")
	}
	input.Header.Set("Content-Disposition", `attachment; filename*=UTF-8''download.zip`)
	if _, err := pipDownloadFilename(input); err == nil {
		t.Fatal("accepted ambiguous filename encoding")
	}
	input.Header.Del("Content-Disposition")
	manager := Pip{versionErr: errors.New("version unavailable")}
	if _, err := manager.selectArchive(input); err == nil {
		t.Fatal("selected archive without a known pip version")
	}
	manager = Pip{version: pm.Version{Major: 26, Minor: 1}}
	input.Probe = func() (pypi.ArchiveSignatures, error) { return pypi.ArchiveSignatures{}, errors.New("probe failed") }
	if _, err := manager.selectArchive(input); err == nil {
		t.Fatal("ignored failed archive probe")
	}
}

func TestPipCachedArchivesRequireUnambiguousInterpretation(t *testing.T) {
	source, _ := url.Parse("https://source.example/download.zip")
	for _, signatures := range []pypi.ArchiveSignatures{{ZIP: true, TAR: pypi.ArchiveGzip}, {RawTAR: true, TAR: pypi.ArchiveGzip}, {ZIP: true}} {
		input := pypi.ArchiveInput{URL: *source, ResponseURL: *source, Header: make(http.Header), CachedHeaders: true, Probe: func() (pypi.ArchiveSignatures, error) { return signatures, nil }}
		format, err := (Pip{version: pm.Version{Major: 26, Minor: 1}}).selectArchive(input)
		ambiguous := signatures.TAR != pypi.ArchiveUnknown
		if (err != nil) != ambiguous || (!ambiguous && format != pypi.ArchiveZIP) {
			t.Fatalf("cached archive=%+v format=%v err=%v", signatures, format, err)
		}
	}
}
