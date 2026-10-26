// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// certificateValidity bounds how long the per-run CA and its leaves are trusted.
// A run is expected to last minutes, so a day comfortably covers long installs
// while keeping leaked public material useless soon after.
const certificateValidity = 24 * time.Hour

// certificateBackdate tolerates small clock skew between SCFW and its child process.
const certificateBackdate = time.Minute

// certificateAuthority is a per-run CA that mints leaf certificates for intercepted
// hosts. Its private key exists only in memory.
type certificateAuthority struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	pem         []byte

	mutex  sync.Mutex
	leaves map[string]*tls.Certificate
}

// newCertificateAuthority creates a CA with a fresh ECDSA P-256 key and a
// random subject suffix. Leaving SerialNumber unset makes x509.CreateCertificate
// generate a random RFC 5280-compliant serial number from crypto/rand.
func newCertificateAuthority() (*certificateAuthority, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}
	nameSuffix := make([]byte, 8)
	if _, err := rand.Read(nameSuffix); err != nil {
		return nil, fmt.Errorf("generate CA name: %w", err)
	}

	issuedAt := time.Now()
	template := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Datadog"},
			CommonName:   "Supply Chain Firewall ephemeral proxy CA " + hex.EncodeToString(nameSuffix),
		},
		NotBefore:             issuedAt.Add(-certificateBackdate),
		NotAfter:              issuedAt.Add(certificateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return &certificateAuthority{
		certificate: certificate,
		privateKey:  privateKey,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves:      make(map[string]*tls.Certificate),
	}, nil
}

// leafCertificate returns a certificate for host signed by the CA, minting and
// caching it on first use. host may be a DNS name or an IP address.
func (ca *certificateAuthority) leafCertificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("cannot issue a certificate for an empty host")
	}

	ca.mutex.Lock()
	defer ca.mutex.Unlock()
	if leaf, ok := ca.leaves[host]; ok {
		return leaf, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf private key: %w", err)
	}

	issuedAt := time.Now()
	template := &x509.Certificate{
		Subject:     pkix.Name{CommonName: host},
		NotBefore:   issuedAt.Add(-certificateBackdate),
		NotAfter:    ca.certificate.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate for %q: %w", host, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate for %q: %w", host, err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{der, ca.certificate.Raw},
		PrivateKey:  privateKey,
		Leaf:        certificate,
	}
	ca.leaves[host] = leaf
	return leaf, nil
}

// serverTLSConfig returns the TLS configuration presented to the client for a
// CONNECT tunnel to hostPort. The SNI server name takes precedence over the
// CONNECT target, since that is the name the client verifies.
func (ca *certificateAuthority) serverTLSConfig(hostPort string) *tls.Config {
	connectHost := hostPort
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		connectHost = host
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				return ca.leafCertificate(hello.ServerName)
			}
			return ca.leafCertificate(connectHost)
		},
	}
}
