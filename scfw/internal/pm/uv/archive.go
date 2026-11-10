// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"path"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
)

// UV selects its source archive extension before downloading. Response MIME,
// Content-Disposition, and redirect filenames do not replace that extension.
// Unsupported legacy formats may still be rejected by uv itself.
func selectArchive(input pypi.ArchiveInput) (pypi.ArchiveFormat, error) {
	filename := strings.ToLower(path.Base(strings.TrimRight(input.URL.Path, "/")))
	if input.RegistryFilename != "" {
		filename = strings.ToLower(input.RegistryFilename)
	}
	for _, entry := range []struct {
		suffix string
		format pypi.ArchiveFormat
	}{
		{".whl", pypi.ArchiveZIP}, {".zip", pypi.ArchiveZIP},
		{".tar.gz", pypi.ArchiveGzip}, {".tgz", pypi.ArchiveGzip},
		{".tar.zst", pypi.ArchiveZstandard}, {".tzst", pypi.ArchiveZstandard},
		{".tar.bz2", pypi.ArchiveBzip2}, {".tbz2", pypi.ArchiveBzip2}, {".tbz", pypi.ArchiveBzip2},
		{".tar.xz", pypi.ArchiveXZ}, {".txz", pypi.ArchiveXZ},
		{".tar.lzma", pypi.ArchiveLZMA}, {".tlz", pypi.ArchiveLZMA},
		{".tar.lz", pypi.ArchiveUnsupported}, {".tar.Z", pypi.ArchiveUnsupported},
		{".tar", pypi.ArchiveTAR},
	} {
		if strings.HasSuffix(filename, strings.ToLower(entry.suffix)) {
			return entry.format, nil
		}
	}
	return pypi.ArchiveUnknown, nil
}
