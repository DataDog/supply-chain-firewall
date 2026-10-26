// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func newTestCertificateAuthority(t *testing.T) *certificateAuthority {
	t.Helper()
	ca, err := newCertificateAuthority()
	if err != nil {
		t.Fatalf("newCertificateAuthority() returned unexpected error: %v", err)
	}
	return ca
}

func TestNewCertificateAuthority(t *testing.T) {
	// Certificates encode times at second precision.
	before := time.Now().Truncate(time.Second)
	ca := newTestCertificateAuthority(t)
	after := time.Now()
	certificate := ca.certificate

	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		t.Error("CA certificate is not marked as a CA")
	}
	if certificate.MaxPathLen != 0 || !certificate.MaxPathLenZero {
		t.Errorf("CA certificate allows intermediate CAs (MaxPathLen = %d)", certificate.MaxPathLen)
	}
	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA certificate cannot sign certificates")
	}
	if certificate.SerialNumber.Sign() <= 0 {
		t.Errorf("CA serial number = %v, want positive", certificate.SerialNumber)
	}
	if notBefore := certificate.NotBefore; notBefore.Before(before.Add(-certificateBackdate)) || notBefore.After(after.Add(-certificateBackdate)) {
		t.Errorf("CA NotBefore = %v, want creation time minus %v", notBefore, certificateBackdate)
	}
	if got, want := certificate.NotAfter.Sub(certificate.NotBefore), certificateValidity+certificateBackdate; got != want {
		t.Errorf("CA validity window = %v, want %v", got, want)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		t.Errorf("CA public key = %T, want ECDSA P-256", certificate.PublicKey)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Errorf("CA certificate is not self-signed: %v", err)
	}
}

func TestNewCertificateAuthorityIsUniquePerCall(t *testing.T) {
	first := newTestCertificateAuthority(t)
	second := newTestCertificateAuthority(t)

	if first.certificate.SerialNumber.Cmp(second.certificate.SerialNumber) == 0 {
		t.Error("two CAs share a serial number")
	}
	if first.certificate.Subject.CommonName == second.certificate.Subject.CommonName {
		t.Error("two CAs share a subject name")
	}
	if first.privateKey.Equal(second.privateKey) {
		t.Error("two CAs share a private key")
	}
}

func TestCertificateAuthorityPEMHoldsOnlyTheCertificate(t *testing.T) {
	ca := newTestCertificateAuthority(t)

	block, rest := pem.Decode(ca.pem)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block = %v, want a CERTIFICATE", block)
	}
	if len(rest) != 0 {
		t.Errorf("PEM has %d trailing bytes, want only the CA certificate", len(rest))
	}
	if string(block.Bytes) != string(ca.certificate.Raw) {
		t.Error("PEM certificate does not match the CA certificate")
	}
}

func TestLeafCertificateVerifiesAgainstCA(t *testing.T) {
	ca := newTestCertificateAuthority(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)

	for _, host := range []string{"registry.npmjs.org", "127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			leaf, err := ca.leafCertificate(host)
			if err != nil {
				t.Fatalf("leafCertificate(%q) returned unexpected error: %v", host, err)
			}
			if leaf.Leaf.IsCA {
				t.Error("leaf certificate is marked as a CA")
			}
			if _, ok := leaf.PrivateKey.(*ecdsa.PrivateKey); !ok {
				t.Errorf("leaf private key = %T, want ECDSA", leaf.PrivateKey)
			}
			_, err = leaf.Leaf.Verify(x509.VerifyOptions{
				DNSName:   host,
				Roots:     roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				t.Errorf("leaf certificate for %q does not verify: %v", host, err)
			}
			if ip := net.ParseIP(host); ip != nil && len(leaf.Leaf.IPAddresses) != 1 {
				t.Errorf("leaf IPAddresses = %v, want [%s]", leaf.Leaf.IPAddresses, host)
			}
		})
	}
}

func TestLeafCertificateIsCachedPerNormalizedHost(t *testing.T) {
	ca := newTestCertificateAuthority(t)

	first, err := ca.leafCertificate("Registry.NPMJS.org.")
	if err != nil {
		t.Fatalf("leafCertificate() returned unexpected error: %v", err)
	}
	second, err := ca.leafCertificate("registry.npmjs.org")
	if err != nil {
		t.Fatalf("leafCertificate() returned unexpected error: %v", err)
	}
	if first != second {
		t.Error("leafCertificate() minted a new certificate for an equivalent host")
	}

	other, err := ca.leafCertificate("pypi.org")
	if err != nil {
		t.Fatalf("leafCertificate() returned unexpected error: %v", err)
	}
	if other == first {
		t.Error("leafCertificate() reused a certificate across hosts")
	}
}

func TestLeafCertificateRejectsEmptyHost(t *testing.T) {
	ca := newTestCertificateAuthority(t)
	if _, err := ca.leafCertificate(""); err == nil {
		t.Error("leafCertificate(\"\") returned no error")
	}
}

func TestServerTLSConfigPrefersServerName(t *testing.T) {
	ca := newTestCertificateAuthority(t)
	config := ca.serverTLSConfig("connect.example:443")

	tests := []struct {
		serverName string
		want       string
	}{
		{serverName: "sni.example", want: "sni.example"},
		{serverName: "", want: "connect.example"},
	}
	for _, tt := range tests {
		certificate, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: tt.serverName})
		if err != nil {
			t.Fatalf("GetCertificate(%q) returned unexpected error: %v", tt.serverName, err)
		}
		if got := certificate.Leaf.DNSNames; len(got) != 1 || got[0] != tt.want {
			t.Errorf("GetCertificate(%q) DNSNames = %v, want [%s]", tt.serverName, got, tt.want)
		}
	}
}
