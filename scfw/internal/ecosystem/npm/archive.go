// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
)

// inspectTarball reads the package identity from the root package.json of a
// tarball, the file npm reads after unpacking with its top directory
// stripped. Nothing is extracted. Archives npm cannot unpack and archives
// without a usable manifest return found=false; unsafe or corrupt ones fail.
func inspectTarball(ctx context.Context, body *io.SectionReader) (Artifact, bool, error) {
	var magic [4]byte
	n, _ := body.ReadAt(magic[:], 0)
	var decoded io.Reader
	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		decoder, err := gzip.NewReader(archive.ContextReader{Ctx: ctx, Reader: body})
		if err != nil {
			return Artifact{}, false, err
		}
		defer func() { _ = decoder.Close() }()
		decoded = decoder
	case n == 4 && bytes.Equal(magic[:], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		// node-tar, which npm unpacks with, also auto-detects Zstandard.
		decoder, err := archive.NewZstdReader(archive.ContextReader{Ctx: ctx, Reader: body})
		if err != nil {
			return Artifact{}, false, err
		}
		defer decoder.Close()
		decoded = decoder
	default:
		// The first header may be a PAX or GNU extension that only parses
		// together with the entry following it.
		if _, err := tar.NewReader(io.NewSectionReader(body, 0, body.Size())).Next(); err != nil {
			return Artifact{}, false, nil
		}
		decoded = body
	}

	expanded := &io.LimitedReader{R: archive.ContextReader{Ctx: ctx, Reader: decoded}, N: archive.MaxExpandedBytes + 1}
	buffered := bufio.NewReader(expanded)
	var manifest []byte
	found := false
	err := archive.WalkTAR(ctx, buffered, func(header *tar.Header, entry io.Reader) error {
		if !isManifestEntry(header.Name) {
			return validEntryName(header.Name)
		}
		if found || header.Typeflag != tar.TypeReg || header.Size > archive.MaxMetadataBytes {
			return errors.New("ambiguous, irregular or oversized npm package manifest")
		}
		var err error
		manifest, err = io.ReadAll(io.LimitReader(entry, archive.MaxMetadataBytes+1))
		found = true
		return err
	})
	if err == nil {
		// Reading to the end validates the compression checksum and catches a
		// truncated stream before the original bytes are released.
		_, err = io.Copy(io.Discard, buffered)
		if err == nil && expanded.N <= 0 {
			err = archive.ErrLimit
		}
	}
	if err != nil || !found {
		return Artifact{}, false, err
	}
	return parseManifest(manifest)
}

func validEntryName(name string) error {
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return errors.New("invalid npm package archive entry")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return errors.New("invalid npm package archive entry")
		}
	}
	return nil
}

// isManifestEntry matches the entry npm unpacks to the package root's
// package.json: node-tar's strip:1 drops the first raw path segment, whatever
// it is (including "."), then resolves the rest against the package root.
func isManifestEntry(name string) bool {
	if validEntryName(name) != nil {
		return false
	}
	_, stripped, found := strings.Cut(name, "/")
	// npm unpacks onto the user's filesystem, which may be case-insensitive.
	return found && strings.EqualFold(path.Clean("/"+stripped), "/package.json")
}

func parseManifest(manifest []byte) (Artifact, bool, error) {
	manifest = bytes.TrimPrefix(manifest, []byte("\xef\xbb\xbf"))
	// npm reads the exact lowercase keys, last duplicate winning; struct
	// decoding would also match "Name" or "NAME".
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(manifest, &fields); err != nil {
		return Artifact{}, false, errors.New("npm package archive has an invalid package.json")
	}
	var name, version string
	_ = json.Unmarshal(fields["name"], &name)
	_ = json.Unmarshal(fields["version"], &version)
	version = strings.TrimLeft(strings.TrimSpace(version), "=v")
	if _, valid := unscopedName(name); !valid || !semverPattern.MatchString(version) {
		return Artifact{}, false, nil
	}
	return Artifact{Name: name, Version: version}, true, nil
}
