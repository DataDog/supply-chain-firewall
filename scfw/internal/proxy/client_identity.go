// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type clientIdentityContextKey struct{}

// identityCertificate supplies an invocation-only TLS client identity. Clients
// which retain their certificate across redirects retain this identity too;
// neither the identity nor its private key is forwarded upstream.
func (ca *certificateAuthority) identityCertificate(directory, identity string) (string, error) {
	if identity == "" || len(identity) > 4096 {
		return "", errors.New("invalid proxy client identity")
	}
	ca.mutex.Lock()
	defer ca.mutex.Unlock()
	if ca.identities == nil {
		ca.identities = map[string]string{}
	}
	path := filepath.Join(directory, fmt.Sprintf("client-%x.pem", sha256.Sum256([]byte(identity))))
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if len(ca.identities) >= 4096 {
		return "", errors.New("too many proxy client identities")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", errors.New("could not generate proxy client identity")
	}
	template := &x509.Certificate{Subject: pkix.Name{CommonName: "SCFW invocation client"},
		NotBefore: time.Now().Add(-certificateBackdate), NotAfter: ca.certificate.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.privateKey)
	if err != nil {
		return "", errors.New("could not generate proxy client certificate")
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", errors.New("could not encode proxy client identity")
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", errors.New("could not write proxy client identity")
	}
	ca.identities[string(der)] = identity
	return path, nil
}

func (ca *certificateAuthority) clientIdentityTLS(config *tls.Config, set func(string)) {
	ca.mutex.Lock()
	enabled := len(ca.identities) > 0
	ca.mutex.Unlock()
	if !enabled {
		return
	}
	config.ClientAuth = tls.RequestClientCert
	config.VerifyConnection = func(state tls.ConnectionState) error {
		// TLS verifies possession of the presented key. Match only the exact
		// certificates minted by this invocation; arbitrary certificates never
		// select a route. Existing client certificates remain accepted.
		if len(state.PeerCertificates) > 0 {
			ca.mutex.Lock()
			identity := ca.identities[string(state.PeerCertificates[0].Raw)]
			ca.mutex.Unlock()
			set(identity)
		}
		return nil
	}
}

func clientIdentity(ctx context.Context) string {
	identity, _ := ctx.Value(clientIdentityContextKey{}).(string)
	return identity
}
