// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

type archiveTestEntry struct {
	name, body string
	typeflag   byte
}

func packageArchive(t *testing.T, format string, entries []archiveTestEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	if format == "zip" {
		writer := zip.NewWriter(&output)
		for _, entry := range entries {
			file, err := writer.Create(entry.name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(file, entry.body); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return output.Bytes()
	}
	var target io.Writer = &output
	var compressed io.WriteCloser
	var err error
	switch format {
	case "gzip":
		compressed = gzip.NewWriter(target)
	case "zstd", "zstd-skippable":
		if format == "zstd-skippable" {
			_, _ = output.Write([]byte{0x5f, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 's', 'k', 'i', 'p'})
		}
		compressed, err = zstd.NewWriter(target, zstd.WithEncoderConcurrency(1))
	case "xz":
		compressed, err = (xz.WriterConfig{DictCap: 1 << 12}).NewWriter(target)
	case "lzma":
		compressed, err = (lzma.WriterConfig{DictCap: 1 << 12}).NewWriter(target)
	}
	if err != nil {
		t.Fatal(err)
	}
	if compressed != nil {
		target = compressed
	}
	writer := tar.NewWriter(target)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.body)), Typeflag: entry.typeflag}
		if entry.typeflag == tar.TypeSymlink {
			header.Size, header.Linkname = 0, "outside-the-archive"
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.typeflag != tar.TypeSymlink {
			if _, err := io.WriteString(writer, entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if compressed != nil {
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func inspectTestArchive(ctx context.Context, body []byte) (Artifact, bool, error) {
	return inspectArchive(ctx, io.NewSectionReader(bytes.NewReader(body), 0, int64(len(body))))
}

func TestArchiveIdentityWithoutExecutingPackageCode(t *testing.T) {
	metadata := readPyPIFixture(t, "archive/PKG-INFO")
	for _, test := range []struct{ format, metadataPath string }{
		{"gzip", "project-1.0/PKG-INFO"},
		{"zstd", "project-1.0/PKG-INFO"},
		{"zstd-skippable", "project-1.0/PKG-INFO"},
		{"tar", "./project-1.0/PKG-INFO"},
		{"tar", strings.Repeat("p", 200) + "/PKG-INFO"},
		{"xz", "project-1.0/PKG-INFO"},
		{"lzma", "project-1.0/PKG-INFO"},
		{"zip", "project-1.0/PKG-INFO"},
		{"zip", "project-1.0.dist-info/METADATA"},
	} {
		t.Run(test.format+test.metadataPath, func(t *testing.T) {
			body := packageArchive(t, test.format, []archiveTestEntry{{name: test.metadataPath, body: metadata}, {name: "project-1.0/pyproject.toml"}})
			artifact, found, err := inspectTestArchive(context.Background(), body)
			if err != nil || !found || artifact.Name != "project" || artifact.Version != "1.0" {
				t.Fatalf("identity=%+v found=%v error=%v", artifact, found, err)
			}
		})
	}
}

func TestArchiveMetadataValidation(t *testing.T) {
	metadata := readPyPIFixture(t, "archive/PKG-INFO")
	for _, test := range []struct{ name, metadata string }{
		{"missing version", strings.ReplaceAll(metadata, "Version: 1.0\n", "")},
		{"invalid name", strings.ReplaceAll(metadata, "Name: project", "Name: project/secret")},
		{"invalid version", strings.ReplaceAll(metadata, "Version: 1.0", "Version: secret")},
		{"duplicate name", "Name: another\n" + metadata},
		{"duplicate version", "Version: 2.0\n" + metadata},
		{"dynamic version", "Dynamic: Version\n" + metadata},
		{"dynamic name", "Dynamic: name\n" + metadata},
		{"oversized metadata", metadata + strings.Repeat("x", int(maxArchiveMetadataBytes))},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []string{"gzip", "zip", "zstd"} {
				body := packageArchive(t, format, []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: test.metadata}})
				if _, _, err := inspectTestArchive(context.Background(), body); err == nil {
					t.Fatalf("%s accepted invalid metadata", format)
				}
			}
		})
	}
	metadata = strings.ReplaceAll(strings.ReplaceAll(metadata, "Name: project", "Name: Project_Name"), "Version: 1.0", "Version: v01.00")
	body := packageArchive(t, "zip", []archiveTestEntry{{name: "Project_Name-1.0/PKG-INFO", body: metadata}})
	artifact, found, err := inspectTestArchive(context.Background(), body)
	if err != nil || !found || artifact.Name != "project-name" || artifact.Version != "1.0" {
		t.Fatalf("identity normalization=%+v %v %v", artifact, found, err)
	}
}

func TestArchiveRejectsAmbiguousAndUnsafeEntries(t *testing.T) {
	metadata := readPyPIFixture(t, "archive/PKG-INFO")
	for _, entries := range [][]archiveTestEntry{
		{{name: "project-1.0/PKG-INFO", body: metadata}, {name: "other-1.0/PKG-INFO", body: metadata}},
		{{name: "project-1.0/pyproject.toml"}},
		{{name: "/outside/PKG-INFO", body: metadata}},
		{{name: "../outside/PKG-INFO", body: metadata}},
		{{name: "project-1.0/PKG-INFO", typeflag: tar.TypeSymlink}},
	} {
		for _, format := range []string{"gzip", "zstd"} {
			body := packageArchive(t, format, entries)
			if _, _, err := inspectTestArchive(context.Background(), body); err == nil {
				t.Fatalf("accepted ambiguous or unsafe %s archive: %+v", format, entries)
			}
		}
	}
}

func TestArchiveLimitsAndNonPackages(t *testing.T) {
	metadata := readPyPIFixture(t, "archive/PKG-INFO")
	valid := packageArchive(t, "gzip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: metadata}})
	for _, body := range [][]byte{
		valid[:len(valid)/2],
		{'P', 'K', 3, 4, 0},
		{0xfd, '7', 'z', 'X', 'Z', 0},
		{'L', 'Z', 'I', 'P', 0},
	} {
		if _, _, err := inspectTestArchive(context.Background(), body); err == nil {
			t.Fatal("corrupt or unsupported archive was accepted")
		}
	}
	var huge bytes.Buffer
	writer := tar.NewWriter(&huge)
	if err := writer.WriteHeader(&tar.Header{Name: "project-1.0/data", Mode: 0600, Size: maxExpandedArchiveBytes + 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectTestArchive(context.Background(), huge.Bytes()); err == nil {
		t.Fatal("unbounded expanded archive was accepted")
	}
	entries := make([]archiveTestEntry, maxArchiveEntries+1)
	for index := range entries {
		entries[index].name = "empty"
	}
	for _, format := range []string{"tar", "zip", "zstd"} {
		if _, _, err := inspectTestArchive(context.Background(), packageArchive(t, format, entries)); err == nil {
			t.Fatalf("%s archive exceeded the entry limit", format)
		}
	}
	lzmaBody := packageArchive(t, "lzma", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: metadata}})
	// A forged 1 GiB dictionary must be rejected before its allocation.
	copy(lzmaBody[1:5], []byte{0, 0, 0, 0x40})
	if _, _, err := inspectTestArchive(context.Background(), lzmaBody); err == nil {
		t.Fatal("unbounded LZMA dictionary was accepted")
	}
	selfExtracting := append([]byte("executable prefix"), packageArchive(t, "zip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: metadata}})...)
	if _, found, err := inspectTestArchive(context.Background(), selfExtracting); err != nil || !found {
		t.Fatalf("ZIP with a prefix lost its identity: %v %v", found, err)
	}
	for _, body := range [][]byte{[]byte("unrelated download"), packageArchive(t, "zip", []archiveTestEntry{{name: "data.csv"}}), packageArchive(t, "zstd", []archiveTestEntry{{name: "data.csv"}})} {
		if _, found, err := inspectTestArchive(context.Background(), body); err != nil || found {
			t.Fatalf("non-package: found=%v error=%v", found, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := inspectTestArchive(ctx, valid); err == nil {
		t.Fatal("canceled inspection succeeded")
	}
}

func TestZstandardArchiveIntegrityAndLimits(t *testing.T) {
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	valid := packageArchive(t, "zstd", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: readPyPIFixture(t, "archive/PKG-INFO")}})
	checksum := bytes.Clone(valid)
	checksum[len(checksum)-1] ^= 1
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"truncated header", valid[:4]},
		{"truncated body", valid[:len(valid)/2]},
		{"truncated checksum", valid[:len(valid)-1]},
		{"invalid checksum", checksum},
		{"trailing corrupt frame", append(bytes.Clone(valid), valid[:4]...)},
		{"ZIP tail cannot disguise stream", append(bytes.Clone(valid), packageArchive(t, "zip", []archiveTestEntry{{name: "data.csv"}})...)},
		{"truncated skippable frame", []byte{0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := inspectTestArchive(context.Background(), test.body); err == nil {
				t.Fatal("corrupt Zstandard archive was accepted")
			}
		})
	}
	// A 256 MiB advertised window exceeds the decoder's 64 MiB memory cap.
	window := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0x90, 1, 0, 0}
	if _, _, err := inspectTestArchive(context.Background(), window); err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("unbounded Zstandard window: %v", err)
	}
	var huge bytes.Buffer
	writer := tar.NewWriter(&huge)
	if err := writer.WriteHeader(&tar.Header{Name: "project-1.0/data", Mode: 0600, Size: maxExpandedArchiveBytes + 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectTestArchive(context.Background(), encoder.EncodeAll(huge.Bytes(), nil)); err == nil {
		t.Fatal("unbounded expanded Zstandard archive was accepted")
	}
	// Valid non-archive streams retain the non-package path.
	if _, found, err := inspectTestArchive(context.Background(), encoder.EncodeAll([]byte("unrelated download"), nil)); err != nil || found {
		t.Fatalf("non-package: %v/%v", found, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := inspectTestArchive(ctx, valid); err == nil {
		t.Fatal("canceled Zstandard inspection succeeded")
	}
}

func TestArchiveInterpretationsHaveDifferentIdentities(t *testing.T) {
	metadata := readPyPIFixture(t, "archive/PKG-INFO")
	inner := packageArchive(t, "zip", []archiveTestEntry{{name: "project-1.0/PKG-INFO", body: metadata}})
	outer := packageArchive(t, "tar", []archiveTestEntry{{name: "allowed-1.0/PKG-INFO", body: strings.ReplaceAll(metadata, "Name: project", "Name: allowed")}, {name: "allowed-1.0/payload.zip", body: string(inner)}})
	// A raw Zstandard block leaves the embedded ZIP visible to ZIP readers.
	payload := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0}
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(outer)))
	block := uint32(len(outer))<<3 | 1
	payload = append(payload, byte(block), byte(block>>8), byte(block>>16))
	payload = append(payload, outer...)
	reader := func() *io.SectionReader { return io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload))) }
	for _, test := range []struct {
		format ArchiveFormat
		name   string
	}{{ArchiveZstandard, "allowed"}, {ArchiveZIP, "project"}} {
		artifact, found, err := inspectArchiveFormat(context.Background(), reader(), test.format)
		if err != nil || !found || artifact.Name != test.name {
			t.Fatalf("format=%v artifact=%+v found=%v err=%v", test.format, artifact, found, err)
		}
	}
	if _, _, err := inspectArchive(context.Background(), reader()); err == nil {
		t.Fatal("accepted ambiguous archive without an adapter selection policy")
	}
}
