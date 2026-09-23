// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestNewCertificateAuthorityCreatesUniqueShortLivedCA(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first, firstPEM, err := newCertificateAuthority(now)
	if err != nil {
		t.Fatalf("newCertificateAuthority() returned error: %v", err)
	}
	second, secondPEM, err := newCertificateAuthority(now)
	if err != nil {
		t.Fatalf("newCertificateAuthority() returned error: %v", err)
	}

	if bytes.Equal(firstPEM, secondPEM) {
		t.Fatal("newCertificateAuthority() returned the same certificate twice")
	}
	if first.PrivateKey == nil || second.PrivateKey == nil {
		t.Fatal("newCertificateAuthority() returned a certificate without a private key")
	}

	block, rest := pem.Decode(firstPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("newCertificateAuthority() did not return one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() returned error: %v", err)
	}
	if !certificate.IsCA {
		t.Fatal("generated certificate is not a CA")
	}
	if certificate.NotAfter.Sub(now) != certificateValidity {
		t.Errorf("certificate validity = %s, want %s", certificate.NotAfter.Sub(now), certificateValidity)
	}
}
