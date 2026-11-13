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
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func fixtureTar(t *testing.T, names []string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := readNpmJSONFixture(t, "archive/root-manifest")
		h := &tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644, Typeflag: tar.TypeReg}
		if kind != 0 {
			h.Typeflag = kind
			h.Size = 0
			h.Linkname = "other"
		}
		if e := tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Size > 0 {
			if _, e := io.WriteString(tw, body); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestArchiveRootAndCompletion(t *testing.T) {
	valid := fixtureTar(t, []string{"package/package.json", "package/example/package.json", "package/node_modules/nested/package.json"}, 0)
	for name, data := range map[string][]byte{"valid": valid, "alternate": fixtureTar(t, []string{"alternate/package.json"}, 0)} {
		t.Run(name, func(t *testing.T) {
			m, _, e := inspectArchive(context.Background(), bytes.NewReader(data))
			if e != nil || len(m) == 0 {
				t.Fatalf("%v", e)
			}
		})
	}
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 0xff
	cases := map[string][]byte{"missing": fixtureTar(t, []string{"package/example/package.json"}, 0), "case alias": fixtureTar(t, []string{"package/package.json", "package/PACKAGE.JSON"}, 0), "duplicate": fixtureTar(t, []string{"package/package.json", "package/package.json"}, 0), "link": fixtureTar(t, []string{"package/package.json"}, tar.TypeSymlink), "hardlink": fixtureTar(t, []string{"package/package.json"}, tar.TypeLink), "traversal": fixtureTar(t, []string{"package/../package.json"}, 0), "multiple roots": fixtureTar(t, []string{"package/package.json", "other/package.json"}, 0), "checksum": corrupt, "truncated": valid[:len(valid)-4], "concatenated": append(bytes.Clone(valid), valid...), "trailing": append(bytes.Clone(valid), 1)}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, e := inspectArchive(context.Background(), bytes.NewReader(data)); e == nil {
				t.Fatal("accepted invalid archive")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := inspectArchive(ctx, bytes.NewReader(valid)); e == nil {
		t.Fatal("ignored cancellation")
	}
	old := maxArchiveBytes
	maxArchiveBytes = 512
	t.Cleanup(func() { maxArchiveBytes = old })
	if _, _, e := inspectArchive(context.Background(), bytes.NewReader(valid)); !errors.Is(e, errInspectionLimit) {
		t.Fatalf("decoded bound lost typed verification limit: %v", e)
	}
}
func TestIntegrityStrengthAndLegacy(t *testing.T) {
	body := []byte("exact tarball bytes")
	strong := sha512.Sum512(body)
	weak := sha1.Sum(body)
	good := "sha512-" + base64.StdEncoding.EncodeToString(strong[:])
	bad := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))
	legacy := hex.EncodeToString(weak[:])
	for _, c := range []struct {
		sri, sha string
		want     bool
	}{{good, "", true}, {bad + " sha1-" + base64.StdEncoding.EncodeToString(weak[:]), "", false}, {"", legacy, true}, {"sha999-AAAA", "", false}, {"sha512-invalid", "", false}, {"", "invalid", false}} {
		_, e := checkIntegrity(bytes.NewReader(body), c.sri, c.sha)
		if (e == nil) != c.want {
			t.Fatalf("integrity=%s error=%v", strings.Split(c.sri, "-")[0], e)
		}
	}
	available, e := checkIntegrity(bytes.NewReader(body), "", "")
	if available || e != nil {
		t.Fatal("missing integrity must be distinguished")
	}
}

func TestIntegrityReadHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := bytes.NewReader([]byte("bytes must not be read after cancellation"))
	reader := artifactContextReadSeeker{artifactContextReader: artifactContextReader{ctx: ctx, reader: body}, Seeker: body}
	_, e := checkIntegrity(reader, "sha512-"+base64.StdEncoding.EncodeToString(make([]byte, 64)), "")
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("digest read ignored cancellation: %v", e)
	}
}
