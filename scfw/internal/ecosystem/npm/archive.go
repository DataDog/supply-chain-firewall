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
	"strconv"
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
			// node-tar skips invalid blocks and keeps reading, so any valid
			// header in the body makes it an archive Go cannot read the same way.
			if found, err := containsTarHeader(ctx, body); found || err != nil {
				return Artifact{}, false, errors.Join(errors.New("unreadable npm tar archive"), err)
			}
			return Artifact{}, false, nil
		}
		decoded = body
	}

	expanded := &io.LimitedReader{R: archive.ContextReader{Ctx: ctx, Reader: decoded}, N: archive.MaxExpandedBytes + 1}
	buffered := bufio.NewReader(expanded)
	var manifest []byte
	found := false
	headers := &headerRecorder{reader: buffered}
	err := archive.WalkTAR(ctx, headers, func(header *tar.Header, entry io.Reader) error {
		if err := headers.check(header); err != nil {
			return err
		}
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

const tarBlock = 512

// containsTarHeader reports whether any 512-byte block of body is a non-zero
// block with a valid tar header checksum.
func containsTarHeader(ctx context.Context, body *io.SectionReader) (bool, error) {
	reader := bufio.NewReaderSize(archive.ContextReader{Ctx: ctx, Reader: io.NewSectionReader(body, 0, body.Size())}, 64<<10)
	block := make([]byte, tarBlock)
	for {
		if _, err := io.ReadFull(reader, block); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return false, nil
			}
			return false, err
		}
		if validHeaderChecksum(block) {
			return true, nil
		}
	}
}

func validHeaderChecksum(block []byte) bool {
	if bytes.Count(block, []byte{0}) == len(block) {
		return false
	}
	field := strings.Trim(string(block[148:156]), " \x00")
	want, err := strconv.ParseInt(field, 8, 64)
	if field == "" || err != nil {
		return false
	}
	var unsigned, signed int64
	for index, character := range block {
		if index >= 148 && index < 156 {
			character = ' '
		}
		unsigned += int64(character)
		signed += int64(int8(character))
	}
	return want == unsigned || want == signed
}

// headerRecorder keeps the raw header blocks Go's tar reader consumes before
// each entry. Go merges every PAX and GNU extension; node-tar merges only the
// last local PAX header, lets PAX override a GNU long name, and ignores paths
// with newlines. Sequences where those rules can disagree are rejected rather
// than reimplementing node-tar.
type headerRecorder struct {
	reader       io.Reader
	offset, mark int64
	recorded     []byte
}

func (r *headerRecorder) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if start := max(r.mark-r.offset, 0); start < int64(n) {
		r.recorded = append(r.recorded, buffer[start:n]...)
	}
	r.offset += int64(n)
	if int64(len(r.recorded)) > 2*archive.MaxMetadataBytes {
		return n, errors.New("npm tar extended headers exceed inspection limit")
	}
	return n, err
}

// check validates the header blocks read since the previous entry's data.
func (r *headerRecorder) check(header *tar.Header) error {
	recorded := r.recorded
	r.recorded, r.mark = nil, r.offset+(header.Size+tarBlock-1)/tarBlock*tarBlock
	if header.Typeflag == tar.TypeXGlobalHeader {
		return errors.New("npm tar archive has a global PAX header")
	}
	extensions, pax, gnu := 0, false, false
	for len(recorded) > tarBlock {
		block := recorded[:tarBlock]
		field := strings.Trim(string(block[124:136]), " \x00")
		size, err := strconv.ParseInt(field, 8, 64)
		if block[124]&0x80 != 0 || err != nil || size < 0 || size > int64(len(recorded)) {
			return errors.New("invalid npm tar extended header")
		}
		switch block[156] {
		case tar.TypeXHeader:
			pax = true
			if err := checkPAXPaths(recorded[tarBlock : tarBlock+size]); err != nil {
				return err
			}
		case tar.TypeGNULongName, tar.TypeGNULongLink:
			gnu = true
		}
		extensions++
		recorded = recorded[min(tarBlock+(size+tarBlock-1)/tarBlock*tarBlock, int64(len(recorded))):]
	}
	if extensions > 1 || (pax && gnu) {
		return errors.New("ambiguous npm tar extended headers")
	}
	return nil
}

func checkPAXPaths(records []byte) error {
	for len(records) > 0 {
		lengthField, _, found := bytes.Cut(records, []byte(" "))
		length, err := strconv.Atoi(string(lengthField))
		if !found || err != nil || length <= len(lengthField)+1 || length > len(records) {
			return errors.New("invalid npm tar PAX record")
		}
		key, value, _ := strings.Cut(string(records[len(lengthField)+1:length-1]), "=")
		if (key == "path" || key == "linkpath") && strings.ContainsAny(value, "\n\x00") {
			return errors.New("npm tar PAX path contains a newline or NUL")
		}
		records = records[length:]
	}
	return nil
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
