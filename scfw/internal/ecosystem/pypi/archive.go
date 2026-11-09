// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/textproto"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

const (
	// MaxArtifactBytes bounds wire and HTTP-decoded opaque downloads. Known
	// distribution filenames continue to be evaluated before downloading.
	MaxArtifactBytes        int64 = 512 << 20
	maxExpandedArchiveBytes int64 = 1 << 30
	maxArchiveMetadataBytes int64 = 1 << 20
	maxArchiveEntries             = 10000
)

type archiveScan struct {
	artifact      Artifact
	found, source bool
}

// inspectArchive reads package metadata without extracting files or executing
// build hooks. Non-package downloads return found=false. Python source archives
// without usable metadata fail closed, including source trees accepted by pip.
func inspectArchive(ctx context.Context, body *io.SectionReader) (Artifact, bool, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, false, err
	}
	var signature [512]byte
	n, _ := body.ReadAt(signature[:], 0)
	// Older source archive formats remain supported by the filename path.
	// An opaque archive in a format we cannot inspect must never pass silently.
	for _, magic := range [][]byte{{'L', 'Z', 'I', 'P'}, {0x1f, 0x9d}} {
		if n >= len(magic) && bytes.Equal(signature[:len(magic)], magic) {
			return Artifact{}, false, errors.New("unsupported opaque Python archive format")
		}
	}
	var reader io.Reader = body
	// Zstandard permits skippable frames before its first compressed frame.
	if n >= 4 && (bytes.Equal(signature[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) ||
		(signature[0]&0xf0 == 0x50 && bytes.Equal(signature[1:4], []byte{0x2a, 0x4d, 0x18}))) {
		decoder, err := zstd.NewReader(archiveContextReader{ctx, reader},
			zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return Artifact{}, false, err
		}
		defer decoder.Close()
		expanded := &io.LimitedReader{R: archiveContextReader{ctx, decoder}, N: maxExpandedArchiveBytes + 1}
		artifact, found, err := inspectTARContent(ctx, expanded)
		if err == nil {
			// TAR ends before the compression stream. Read through its checksum
			// and any following frames before releasing the original bytes.
			_, err = io.Copy(io.Discard, expanded)
			if err == nil && expanded.N <= 0 {
				err = errors.New("expanded Python archive exceeds inspection limit")
			}
		}
		return artifact, found, err
	}
	if archive, err := zip.NewReader(body, body.Size()); err == nil {
		return inspectZIP(ctx, archive)
	} else if n >= 4 && bytes.Equal(signature[:4], []byte{'P', 'K', 3, 4}) {
		return Artifact{}, false, err
	}
	if n >= 2 && signature[0] == 0x1f && signature[1] == 0x8b {
		decoder, err := gzip.NewReader(reader)
		if err != nil {
			return Artifact{}, false, err
		}
		defer func() { _ = decoder.Close() }()
		reader = decoder
	} else if n >= 3 && string(signature[:3]) == "BZh" {
		reader = bzip2.NewReader(reader)
	} else if n >= 6 && bytes.Equal(signature[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0}) {
		decoder, err := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(reader)
		if err != nil {
			return Artifact{}, false, err
		}
		reader = decoder
	} else if n >= lzma.HeaderLen && lzma.ValidHeader(signature[:lzma.HeaderLen]) {
		decoder, err := (lzma.ReaderConfig{DictCap: 64 << 20}).NewReader(reader)
		if err != nil {
			return Artifact{}, false, err
		}
		reader = decoder
	}
	return inspectTARContent(ctx, reader)
}

func inspectTARContent(ctx context.Context, reader io.Reader) (Artifact, bool, error) {
	buffered := bufio.NewReaderSize(reader, 512)
	header, err := buffered.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) {
		return Artifact{}, false, err
	}
	if len(header) < 512 {
		return Artifact{}, false, nil
	}
	if string(header[257:262]) != "ustar" {
		if _, err := tar.NewReader(bytes.NewReader(header)).Next(); err != nil {
			return Artifact{}, false, nil
		}
	}
	return inspectTAR(ctx, buffered)
}

func inspectTAR(ctx context.Context, reader io.Reader) (Artifact, bool, error) {
	limited := &io.LimitedReader{R: archiveContextReader{ctx, reader}, N: maxExpandedArchiveBytes + 1}
	archive := tar.NewReader(limited)
	scan := archiveScan{}
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return Artifact{}, false, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			if limited.N <= 0 {
				return Artifact{}, false, errors.New("expanded Python archive exceeds inspection limit")
			}
			return scan.result()
		}
		if err != nil {
			return Artifact{}, false, err
		}
		if entries >= maxArchiveEntries || header.Size > limited.N {
			return Artifact{}, false, errors.New("python archive exceeds inspection limit")
		}
		metadata, err := scan.entry(header.Name)
		if err != nil {
			return Artifact{}, false, err
		}
		if !metadata {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return Artifact{}, false, errors.New("python archive metadata is not a regular file")
		}
		if err := scan.readMetadata(ctx, archive, header.Size); err != nil {
			return Artifact{}, false, err
		}
	}
}

func inspectZIP(ctx context.Context, archive *zip.Reader) (Artifact, bool, error) {
	if len(archive.File) > maxArchiveEntries {
		return Artifact{}, false, errors.New("python archive exceeds entry limit")
	}
	scan := archiveScan{}
	var expanded uint64
	for _, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return Artifact{}, false, err
		}
		if file.UncompressedSize64 > uint64(maxExpandedArchiveBytes)-expanded {
			return Artifact{}, false, errors.New("expanded Python archive exceeds inspection limit")
		}
		expanded += file.UncompressedSize64
		metadata, err := scan.entry(file.Name)
		if err != nil {
			return Artifact{}, false, err
		}
		if !metadata {
			continue
		}
		if !file.Mode().IsRegular() {
			return Artifact{}, false, errors.New("python archive metadata is not a regular file")
		}
		reader, err := file.Open()
		if err != nil {
			return Artifact{}, false, err
		}
		err = scan.readMetadata(ctx, reader, int64(file.UncompressedSize64))
		_ = reader.Close()
		if err != nil {
			return Artifact{}, false, err
		}
	}
	return scan.result()
}

func (scan *archiveScan) entry(name string) (bool, error) {
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false, errors.New("invalid Python archive entry")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return false, errors.New("invalid Python archive entry")
		}
	}
	name = path.Clean(name)
	base := strings.ToLower(path.Base(name))
	if base == "pyproject.toml" || base == "setup.py" || base == "setup.cfg" {
		scan.source = true
	}
	parts := strings.Split(name, "/")
	return len(parts) == 2 && (parts[1] == "PKG-INFO" ||
		(strings.HasSuffix(parts[0], ".dist-info") && parts[1] == "METADATA")), nil
}

func (scan *archiveScan) readMetadata(ctx context.Context, reader io.Reader, size int64) error {
	if size > maxArchiveMetadataBytes || scan.found {
		return errors.New("oversized or ambiguous Python archive metadata")
	}
	body, err := io.ReadAll(io.LimitReader(archiveContextReader{ctx, reader}, maxArchiveMetadataBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxArchiveMetadataBytes {
		return errors.New("python archive metadata exceeds inspection limit")
	}
	// Core metadata can end at EOF without the blank line expected by MIMEHeader.
	header, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(body, '\n', '\n')))).ReadMIMEHeader()
	if err != nil || len(header.Values("Name")) != 1 || len(header.Values("Version")) != 1 {
		return errors.New("python archive has invalid package identity")
	}
	name := strings.TrimSpace(header.Get("Name"))
	version, valid := canonicalPyPIVersion(strings.TrimSpace(header.Get("Version")))
	if !pyPIProjectName.MatchString(name) || !valid {
		return errors.New("python archive has invalid package identity")
	}
	for _, dynamic := range header.Values("Dynamic") {
		for _, field := range strings.Split(dynamic, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "Name") || strings.EqualFold(strings.TrimSpace(field), "Version") {
				return errors.New("python archive identity cannot be dynamic")
			}
		}
	}
	scan.artifact, scan.found = Artifact{Name: NormalizeName(name), Version: version}, true
	return nil
}

func (scan archiveScan) result() (Artifact, bool, error) {
	if !scan.found && scan.source {
		return Artifact{}, false, errors.New("python source archive has no usable package metadata")
	}
	return scan.artifact, scan.found, nil
}

type archiveContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader archiveContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
