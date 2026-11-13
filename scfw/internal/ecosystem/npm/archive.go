// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	"io"
	"path"
	"strings"
)

var errInspectionLimit = errors.New("npm artifact inspection limit exceeded")

var maxArtifactBytes int64 = 256 << 20
var maxArchiveBytes int64 = 1 << 30
var maxArchiveEntries = 10000

type boundedArchiveReader struct {
	ctx  context.Context
	r    io.Reader
	left int64
}

func (r *boundedArchiveReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if r.left <= 0 {
		return 0, errInspectionLimit
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, e := r.r.Read(p)
	r.left -= int64(n)
	return n, e
}

// inspectArchive consumes the entire single gzip member, including its trailer.
// Nothing is extracted. A single common prefix establishes npm's installed root.
func inspectArchive(ctx context.Context, reader io.Reader) ([]byte, ArchiveFacts, error) {
	var facts ArchiveFacts
	br := bufio.NewReader(artifactContextReader{ctx: ctx, reader: reader})
	gz, e := gzip.NewReader(br)
	if e != nil {
		return nil, facts, errors.New("invalid gzip archive")
	}
	defer gz.Close() //nolint:errcheck
	gz.Multistream(false)
	bounded := &boundedArchiveReader{ctx, gz, maxArchiveBytes}
	tr := tar.NewReader(bounded)
	root := ""
	seen := map[string]bool{}
	fold := cases.Fold()
	var manifest []byte
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			if errors.Is(e, errInspectionLimit) {
				return nil, facts, errInspectionLimit
			}
			return nil, facts, errors.New("invalid tar archive")
		}
		if count >= maxArchiveEntries {
			return nil, facts, errInspectionLimit
		}
		n := strings.TrimSuffix(h.Name, "/")
		if n == "" || path.IsAbs(n) || strings.ContainsRune(n, 92) || path.Clean(n) != n || strings.IndexByte(n, 0) >= 0 {
			return nil, facts, errors.New("ambiguous archive path")
		}
		parts := strings.Split(n, "/")
		if parts[0] == ".." || parts[0] == "." {
			return nil, facts, errors.New("unsafe archive path")
		}
		if root == "" {
			root = parts[0]
		}
		if root != parts[0] {
			return nil, facts, errors.New("ambiguous archive root")
		}
		effectivePath := fold.String(norm.NFC.String(n))
		if seen[effectivePath] {
			return nil, facts, errors.New("duplicate archive entry")
		}
		seen[effectivePath] = true
		if len(parts) == 1 && h.Typeflag != tar.TypeDir {
			return nil, facts, errors.New("archive needs a root prefix")
		}
		if len(parts) == 2 {
			canonical := fold.String(norm.NFC.String(parts[1]))
			if (canonical == "package.json" || canonical == "npm-shrinkwrap.json" || strings.HasSuffix(canonical, ".gyp")) && canonical != parts[1] {
				return nil, facts, errors.New("noncanonical installation-sensitive archive path")
			}
		}
		if len(parts) == 2 && strings.HasSuffix(parts[1], ".gyp") {
			if h.Typeflag != tar.TypeReg {
				return nil, facts, errors.New("ambiguous native build file")
			}
			facts.BindingGyp = true
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "package.json":
				if h.Size > maxManifestBytes {
					return nil, facts, errInspectionLimit
				}
				if h.Typeflag != tar.TypeReg {
					return nil, facts, errors.New("invalid root manifest")
				}
				manifest, e = io.ReadAll(tr)
				if e != nil {
					if errors.Is(e, errInspectionLimit) {
						return nil, facts, errInspectionLimit
					}
					return nil, facts, errors.New("incomplete root manifest")
				}
			case "binding.gyp":
				if h.Typeflag != tar.TypeReg {
					return nil, facts, errors.New("ambiguous native build file")
				}
				facts.BindingGyp = true
			case "npm-shrinkwrap.json":
				if h.Typeflag != tar.TypeReg {
					return nil, facts, errors.New("ambiguous shrinkwrap")
				}
				facts.Shrinkwrap = true
			}
		}
	}
	// tar stops at its end markers. Permit only zero padding after them, while
	// forcing gzip checksum validation; reject appended tar streams or payloads.
	buf := make([]byte, 32<<10)
	for {
		n, e := bounded.Read(buf)
		for _, v := range buf[:n] {
			if v != 0 {
				return nil, facts, errors.New("trailing archive payload")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			if errors.Is(e, errInspectionLimit) {
				return nil, facts, errInspectionLimit
			}
			return nil, facts, errors.New("invalid gzip completion")
		}
	}
	if _, e = br.ReadByte(); e != io.EOF {
		return nil, facts, errors.New("concatenated or trailing gzip payload")
	}
	if manifest == nil {
		return nil, facts, errors.New("missing root manifest")
	}
	return manifest, facts, nil
}

// These wrappers apply cancellation to compressed reads and digest passes,
// including long sequences of empty HTTP gzip members in a buffered response.
type artifactContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r artifactContextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(p)
}

type artifactContextReadSeeker struct {
	artifactContextReader
	io.Seeker
}
