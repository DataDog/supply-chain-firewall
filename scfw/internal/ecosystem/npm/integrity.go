// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"crypto/sha1" // npm's legacy dist.shasum requires SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strings"
)

// checkIntegrity prefers the strongest supported algorithm across the entire
// SRI set. A bad stronger digest cannot fall back to a weaker one.
func checkIntegrity(reader io.ReadSeeker, sri, shasum string) (bool, error) {
	if sri == "" && shasum == "" {
		return false, nil
	}
	if sri == "" {
		raw, e := hex.DecodeString(shasum)
		if e != nil || len(raw) != 20 {
			return true, errors.New("invalid advertised integrity")
		}
		sri = "sha1-" + base64.StdEncoding.EncodeToString(raw)
	}
	strength := map[string]int{"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}
	best := 0
	algorithm := ""
	digests := [][]byte{}
	for _, token := range strings.Fields(sri) {
		alg, value, ok := strings.Cut(token, "-")
		if !ok {
			return true, errors.New("invalid advertised integrity")
		}
		rank := strength[alg]
		if rank == 0 {
			continue
		}
		value, _, _ = strings.Cut(value, "?")
		raw, e := base64.StdEncoding.DecodeString(value)
		sizes := map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
		if e != nil || len(raw) != sizes[alg] {
			return true, errors.New("invalid advertised integrity")
		}
		if rank > best {
			best = rank
			algorithm = alg
			digests = nil
		}
		if rank == best {
			digests = append(digests, raw)
		}
	}
	if best == 0 {
		return true, errors.New("unsupported advertised integrity")
	}
	var h hash.Hash
	switch algorithm {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	}
	if _, e := reader.Seek(0, io.SeekStart); e != nil {
		return true, e
	}
	if _, e := io.Copy(h, reader); e != nil {
		return true, e
	}
	actual := base64.StdEncoding.EncodeToString(h.Sum(nil))
	for _, d := range digests {
		if actual == base64.StdEncoding.EncodeToString(d) {
			return true, nil
		}
	}
	return true, errors.New("artifact integrity mismatch")
}
