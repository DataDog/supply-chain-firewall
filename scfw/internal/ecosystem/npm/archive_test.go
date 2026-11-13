// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/klauspost/compress/zstd"
)

type tarEntry struct {
	name, body string
	typeflag   byte
	size       int64
}

// npmTarball builds an archive in format "gzip", "zstd" or "tar".
func npmTarball(t *testing.T, format string, entries ...tarEntry) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.body)), Typeflag: entry.typeflag}
		if entry.typeflag == tar.TypeSymlink {
			header.Size, header.Linkname = 0, "../outside.json"
		}
		if entry.size != 0 {
			header.Size = entry.size
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil && entries[len(entries)-1].size == 0 {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	switch format {
	case "tar":
		return raw.Bytes()
	case "gzip":
		gzipWriter := gzip.NewWriter(&compressed)
		_, _ = gzipWriter.Write(raw.Bytes())
		_ = gzipWriter.Close()
	case "zstd":
		zstdWriter, err := zstd.NewWriter(&compressed)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = zstdWriter.Write(raw.Bytes())
		_ = zstdWriter.Close()
	}
	return compressed.Bytes()
}

func inspect(t *testing.T, data []byte) (Artifact, bool, error) {
	t.Helper()
	return inspectTarball(context.Background(), io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))))
}

func TestInspectTarballReadsRootManifest(t *testing.T) {
	widget := readNpmFixture(t, "manifest/widget.json")
	for _, tc := range []struct {
		name, format, entry, manifest, wantName string
	}{
		{"registry layout", "gzip", "package/package.json", widget, "@acme/widget"},
		{"codeload layout", "gzip", "widget-0123abc/package.json", widget, "@acme/widget"},
		{"raw tar", "tar", "package/package.json", widget, "@acme/widget"},
		{"zstd", "zstd", "package/package.json", widget, "@acme/widget"},
		{"byte order mark", "gzip", "package/package.json", "\ufeff" + widget, "@acme/widget"},
		{"v-prefixed version", "gzip", "package/package.json", readNpmFixture(t, "manifest/v-prefixed.json"), "widget"},
		{"dot top directory", "gzip", "./package.json", widget, "@acme/widget"},
		{"dot segment after top directory", "gzip", "package/./package.json", widget, "@acme/widget"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := npmTarball(t, tc.format, tarEntry{name: "package/index.js", body: "x"}, tarEntry{name: tc.entry, body: tc.manifest},
				tarEntry{name: "package/lib/package.json", body: "{}"})
			artifact, found, err := inspect(t, data)
			if err != nil || !found || artifact.Name != tc.wantName || artifact.Version != "1.2.3" {
				t.Fatalf("inspectTarball() = %+v, %v, %v; want %s@1.2.3", artifact, found, err, tc.wantName)
			}
		})
	}
}

func TestInspectTarballReadsRawPAXTar(t *testing.T) {
	widget := readNpmFixture(t, "manifest/widget.json")
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	header := &tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(widget)), Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "pax first"}}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write([]byte(widget))
	_ = writer.Close()
	artifact, found, err := inspect(t, raw.Bytes())
	if err != nil || !found || artifact.Name != "@acme/widget" {
		t.Fatalf("inspectTarball() = %+v, %v, %v; want @acme/widget from a PAX-first raw tar", artifact, found, err)
	}
}

func TestInspectTarballAllowsNonPackageDownloads(t *testing.T) {
	for name, data := range map[string][]byte{
		"no manifest":     npmTarball(t, "gzip", tarEntry{name: "node-v20.0.0/include/node/node.h", body: "#pragma once"}),
		"no version":      npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: readNpmFixture(t, "manifest/no-version.json")}),
		"non-archive":     []byte("<html>not a tarball</html>"),
		"nested manifest": npmTarball(t, "gzip", tarEntry{name: "package/sub/package.json", body: readNpmFixture(t, "manifest/widget.json")}),
		// node-tar strips "." as the top directory, leaving package/package.json nested.
		"dot-prefixed nested manifest": npmTarball(t, "gzip", tarEntry{name: "./package/package.json", body: readNpmFixture(t, "manifest/widget.json")}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, found, err := inspect(t, data); found || err != nil {
				t.Fatalf("inspectTarball() found=%v err=%v, want no identity and no error", found, err)
			}
		})
	}
}

func TestInspectTarballRejectsUnsafeArchives(t *testing.T) {
	widget := readNpmFixture(t, "manifest/widget.json")
	entries := make([]tarEntry, archive.MaxEntries+1)
	for index := range entries {
		entries[index] = tarEntry{name: "package/f"}
	}
	valid := npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: widget})
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 0xff
	var window bytes.Buffer
	// A frame header declaring a 1 GiB window must not allocate it.
	window.Write([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x90})
	window.Write(make([]byte, 64))
	var bomb bytes.Buffer
	bombWriter := gzip.NewWriter(&bomb)
	tarWriter := tar.NewWriter(bombWriter)
	_ = tarWriter.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(widget))})
	_, _ = tarWriter.Write([]byte(widget))
	_ = tarWriter.WriteHeader(&tar.Header{Name: "package/zeros", Mode: 0o644, Size: archive.MaxExpandedBytes - 4096})
	zeros := make([]byte, 1<<20)
	for written := int64(0); written < archive.MaxExpandedBytes-4096; written += int64(len(zeros)) {
		chunk := zeros
		if remaining := archive.MaxExpandedBytes - 4096 - written; remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		_, _ = tarWriter.Write(chunk)
	}
	_ = tarWriter.Close()
	_, _ = bombWriter.Write(make([]byte, 1<<20))
	_ = bombWriter.Close()

	for name, data := range map[string][]byte{
		"invalid JSON":       npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: readNpmFixture(t, "manifest/invalid.json")}),
		"two manifests":      npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: widget}, tarEntry{name: "other/package.json", body: widget}),
		"symlink manifest":   npmTarball(t, "gzip", tarEntry{name: "package/package.json", typeflag: tar.TypeSymlink}),
		"parent traversal":   npmTarball(t, "gzip", tarEntry{name: "package/../../etc/x", body: "x"}),
		"oversized manifest": npmTarball(t, "gzip", tarEntry{name: "package/package.json", body: widget + strings.Repeat(" ", int(archive.MaxMetadataBytes))}),
		"too many entries":   npmTarball(t, "gzip", entries...),
		"declared size":      npmTarball(t, "gzip", tarEntry{name: "package/data", size: archive.MaxExpandedBytes + 1}),
		"gzip bomb":          bomb.Bytes(),
		"corrupt checksum":   corrupt,
		"truncated gzip":     valid[:len(valid)-12],
		"zstd window":        window.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := inspect(t, data); err == nil {
				t.Fatal("inspectTarball() returned nil error, want the archive rejected")
			}
		})
	}
}
