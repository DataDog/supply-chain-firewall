// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

// Public-key pins are checked independently of certificate-chain verification.
// The child trusts SCFW's invocation certificate; the origin pin belongs here.
func (s *Settings) pinPublicKey(config *tls.Config, value string) error {
	if value == "" {
		return nil
	}
	var hashes [][]byte
	if strings.HasPrefix(value, "sha256//") {
		for _, pin := range strings.Split(value, ";") {
			encoded, ok := strings.CutPrefix(pin, "sha256//")
			digest, err := base64.StdEncoding.DecodeString(encoded)
			if !ok || err != nil || len(digest) != sha256.Size {
				return errors.New("invalid Git public key pin")
			}
			hashes = append(hashes, digest)
		}
	} else {
		contents, err := os.ReadFile(gitConfigurationPath(value, s.directory, s.home))
		if err != nil || len(contents) > maxConfigurationBytes {
			return errors.New("could not read Git public key pin")
		}
		if block, _ := pem.Decode(contents); block != nil {
			contents = block.Bytes
		}
		publicKey, err := x509.ParsePKIXPublicKey(contents)
		if err != nil {
			rsaKey, rsaErr := x509.ParsePKCS1PublicKey(contents)
			if rsaErr != nil {
				return errors.New("invalid Git public key pin")
			}
			publicKey = rsaKey
		}
		encoded, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return errors.New("invalid Git public key pin")
		}
		digest := sha256.Sum256(encoded)
		hashes = append(hashes, bytes.Clone(digest[:]))
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("missing Git peer public key")
		}
		digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		for _, pin := range hashes {
			if subtle.ConstantTimeCompare(pin, digest[:]) == 1 {
				return nil
			}
		}
		return errors.New("public key does not match the Git pin")
	}
	return nil
}
