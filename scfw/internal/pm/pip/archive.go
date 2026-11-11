// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"errors"
	"mime"
	"path"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// pip 26.1 fixed ZIP-signature precedence (pypa/pip#13870). Older pip versions
// choose ZIP if any ZIP hint matches, even when the filename says TAR.
func (pip Pip) selectArchive(input pypi.ArchiveInput) (pypi.ArchiveFormat, error) {
	if pip.versionErr != nil {
		return pypi.ArchiveUnknown, errors.New("cannot determine pip archive selection rules")
	}
	if input.CachedHeaders {
		signatures, err := input.Probe()
		if err != nil {
			return pypi.ArchiveUnknown, err
		}
		if (signatures.ZIP && signatures.TAR != pypi.ArchiveUnknown) || (signatures.RawTAR && signatures.TAR != pypi.ArchiveTAR) {
			return pypi.ArchiveUnknown, errors.New("cannot determine cached pip archive interpretation")
		}
	}
	filename, err := pipDownloadFilename(input)
	if err != nil {
		return pypi.ArchiveUnknown, err
	}
	contentType := input.Header.Get("Content-Type")
	zipHint := contentType == "application/zip" || strings.HasSuffix(filename, ".zip") || strings.HasSuffix(filename, ".whl")
	if pip.version.LessThan(pm.Version{Major: 26, Minor: 1}) {
		if zipHint {
			return pypi.ArchiveZIP, nil
		}
		signatures, err := input.Probe()
		if err != nil {
			return pypi.ArchiveUnknown, err
		}
		if signatures.ZIP {
			return pypi.ArchiveZIP, nil
		}
	} else {
		if contentType == "application/zip" {
			return pypi.ArchiveZIP, nil
		}
		if contentType == "application/x-gzip" {
			return pipTARFormat(input, filename)
		}
		if zipHint {
			return pypi.ArchiveZIP, nil
		}
	}
	for _, suffix := range []string{".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma"} {
		if strings.HasSuffix(filename, suffix) {
			return pipTARFormat(input, filename)
		}
	}
	if contentType == "application/x-gzip" {
		return pipTARFormat(input, filename)
	}
	signatures, err := input.Probe()
	if err != nil {
		return pypi.ArchiveUnknown, err
	}
	if signatures.TAR == pypi.ArchiveZstandard || signatures.TAR == pypi.ArchiveUnsupported {
		return pypi.ArchiveUnknown, errors.New("unsupported opaque pip source archive")
	}
	if signatures.ZIP && signatures.TAR != pypi.ArchiveUnknown {
		return pypi.ArchiveUnknown, errors.New("ambiguous pip archive format")
	}
	if signatures.ZIP {
		return pypi.ArchiveZIP, nil
	}
	return signatures.TAR, nil
}

func pipTARFormat(input pypi.ArchiveInput, filename string) (pypi.ArchiveFormat, error) {
	switch {
	case strings.HasSuffix(filename, ".gz") || strings.HasSuffix(filename, ".tgz"):
		return pypi.ArchiveGzip, nil
	case strings.HasSuffix(filename, ".tar.bz2") || strings.HasSuffix(filename, ".tbz"):
		return pypi.ArchiveBzip2, nil
	}
	// pip opens .tar files in Python's "r" mode, which auto-detects compression.
	// Prefer the compressed interpretation even when the bytes also form raw TAR.
	signatures, err := input.Probe()
	if err != nil {
		return pypi.ArchiveUnknown, err
	}
	for _, suffix := range []string{".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma"} {
		if strings.HasSuffix(filename, suffix) {
			// Python's LZMAFile accepts both XZ and legacy LZMA in r:xz mode.
			if signatures.TAR == pypi.ArchiveLZMA {
				return pypi.ArchiveLZMA, nil
			}
			return pypi.ArchiveXZ, nil
		}
	}
	switch signatures.TAR {
	case pypi.ArchiveTAR, pypi.ArchiveGzip, pypi.ArchiveBzip2, pypi.ArchiveXZ, pypi.ArchiveLZMA:
		return signatures.TAR, nil
	}
	return pypi.ArchiveUnknown, errors.New("unsupported opaque pip source archive")
}

// Match pip's download filename: Content-Disposition overrides the original
// URL; missing extensions use MIME first, then the redirected URL's extension.
func pipDownloadFilename(input pypi.ArchiveInput) (string, error) {
	filename := path.Base(strings.TrimRight(input.URL.Path, "/"))
	if disposition := input.Header.Get("Content-Disposition"); disposition != "" {
		// Python email and Go mime do not agree on every extended filename form.
		// Reject those here rather than evaluate a different interpretation.
		if strings.Contains(strings.ToLower(disposition), "filename*") {
			return "", errors.New("unsupported pip download filename encoding")
		}
		_, parameters, err := mime.ParseMediaType(disposition)
		if err != nil {
			return "", errors.New("cannot determine pip download filename")
		}
		if parameters["filename"] != "" {
			filename = path.Base(parameters["filename"])
		}
	}
	extension := path.Ext(filename)
	// Python treats dotfiles as extensionless.
	if extension == filename {
		extension = ""
	}
	if extension == "" {
		switch input.Header.Get("Content-Type") {
		case "application/zip":
			extension = ".zip"
		case "application/x-gzip", "application/gzip":
			extension = ".gz"
		case "application/x-tar":
			extension = ".tar"
		case "application/x-bzip2":
			extension = ".bz2"
		case "application/x-xz":
			extension = ".xz"
		case "application/octet-stream":
			extension = ".bin"
		}
		if extension == "" {
			// Python's MIME registry also reads host-specific mappings. An
			// unknown MIME plus a redirect suffix cannot be reproduced safely.
			if input.Header.Get("Content-Type") != "" && input.URL.String() != input.ResponseURL.String() && path.Ext(input.ResponseURL.Path) != "" {
				return "", errors.New("cannot determine pip MIME filename across redirect")
			}
			extension = path.Ext(input.ResponseURL.Path)
		}
		filename += extension
	}
	return strings.ToLower(filename), nil
}
