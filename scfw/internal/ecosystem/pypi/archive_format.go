// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/ulikunitz/xz/lzma"
)

// ArchiveFormat identifies a reader, not a package manager's selection policy.
type ArchiveFormat uint8

const (
	ArchiveUnknown ArchiveFormat = iota
	ArchiveZIP
	ArchiveTAR
	ArchiveGzip
	ArchiveBzip2
	ArchiveXZ
	ArchiveLZMA
	ArchiveZstandard
	ArchiveUnsupported
)

// ArchiveSignatures reports independent interpretations of the same bytes.
// Compressed signatures are candidates; the selected reader validates the data.
type ArchiveSignatures struct {
	ZIP    bool
	TAR    ArchiveFormat
	RawTAR bool
}

// ArchiveInput supplies download provenance and lazy bounded format probes.
// URL is the original URL, while ResponseURL is the final HTTP request URL.
// The adapter owns filename, content-type, and version-specific precedence.
type ArchiveInput struct {
	// RegistryFilename is an advertised distribution name, when available.
	RegistryFilename string
	// CachedHeaders marks a 304 whose original cached headers are unavailable.
	CachedHeaders bool
	URL           url.URL
	ResponseURL   url.URL
	Header        http.Header
	Probe         func() (ArchiveSignatures, error)
}

// ArchiveSelector applies the package manager's download interpretation rules.
// It runs synchronously and may call Probe more than once without rereading data.
type ArchiveSelector func(ArchiveInput) (ArchiveFormat, error)

func probeArchive(ctx context.Context, body *io.SectionReader) (ArchiveSignatures, error) {
	if err := ctx.Err(); err != nil {
		return ArchiveSignatures{}, err
	}
	var signature [512]byte
	n, _ := body.ReadAt(signature[:], 0)
	var result ArchiveSignatures
	if archive, err := zip.NewReader(body, body.Size()); err == nil {
		if len(archive.File) > maxArchiveEntries {
			return result, errors.New("too many Python archive entries")
		}
		result.ZIP = true
	} else if n >= 4 && bytes.Equal(signature[:4], []byte{'P', 'K', 3, 4}) {
		result.ZIP = true
	}
	switch {
	case n >= 4 && (bytes.Equal(signature[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) || (signature[0]&0xf0 == 0x50 && bytes.Equal(signature[1:4], []byte{0x2a, 0x4d, 0x18}))):
		result.TAR = ArchiveZstandard
	case n >= 2 && bytes.Equal(signature[:2], []byte{0x1f, 0x8b}):
		result.TAR = ArchiveGzip
	case n >= 3 && string(signature[:3]) == "BZh":
		result.TAR = ArchiveBzip2
	case n >= 6 && bytes.Equal(signature[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		result.TAR = ArchiveXZ
	case (n >= 4 && string(signature[:4]) == "LZIP") || (n >= 2 && bytes.Equal(signature[:2], []byte{0x1f, 0x9d})):
		result.TAR = ArchiveUnsupported
	case n >= lzma.HeaderLen && lzma.ValidHeader(signature[:lzma.HeaderLen]):
		result.TAR = ArchiveLZMA
	}
	if n == len(signature) {
		// PAX and GNU extension headers may require more than the first block.
		raw := tar.NewReader(archiveContextReader{ctx, io.NewSectionReader(body, 0, body.Size())})
		if _, err := raw.Next(); err == nil {
			result.RawTAR = true
			if result.TAR == ArchiveUnknown {
				result.TAR = ArchiveTAR
			}
		}
	}
	return result, nil
}

// Without an adapter policy, accept only an unambiguous interpretation.
func uniqueArchiveFormat(signatures ArchiveSignatures) (ArchiveFormat, error) {
	if (signatures.ZIP && signatures.TAR != ArchiveUnknown) || (signatures.RawTAR && signatures.TAR != ArchiveTAR) {
		return ArchiveUnknown, errors.New("ambiguous Python archive format")
	}
	if signatures.ZIP {
		return ArchiveZIP, nil
	}
	return signatures.TAR, nil
}
