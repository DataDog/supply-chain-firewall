// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCAPEM(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTLSUsesSystemRootsByDefault(t *testing.T) {
	isolatedEnvironment(t)
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []string{"", "--native-tls", "--no-native-tls", "--system-certs", "--no-system-certs"} {
		t.Run(flags, func(t *testing.T) {
			args := []string{"sync"}
			if flags != "" {
				args = append(args, flags)
			}
			config, err := (UV{}).tlsConfig(args)
			if err != nil || !config.RootCAs.Equal(system) {
				t.Fatalf("system trust was not selected: %v", err)
			}
		})
	}
}

func TestCustomSourcesReplaceDefaultRoots(t *testing.T) {
	isolatedEnvironment(t)
	first := testCAPEM(t, "first test CA")
	second := testCAPEM(t, "second test CA")
	file := filepath.Join(t.TempDir(), "ca.pem")
	directory := t.TempDir()
	if err := os.WriteFile(file, first, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), second, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("cwd.pem", first, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, file, dir string
		args            []string
		want            int
		failure         bool
	}{
		{name: "file only", file: file, want: 1},
		{name: "directory only", dir: directory, want: 1},
		{name: "both environment sources", file: file, dir: directory, want: 2},
		{name: "explicit cert replaces environment", file: file, dir: directory, args: []string{"pip", "install", "--cert", file}, want: 1},
		{name: "missing environment file", file: filepath.Join(directory, "missing")},
		{name: "missing environment directory", dir: filepath.Join(directory, "missing")},
		{name: "empty directory", dir: t.TempDir()},
		{name: "empty directory entries do not mean cwd", dir: string(os.PathListSeparator)},
		{name: "missing explicit cert", args: []string{"pip", "install", "--cert", filepath.Join(directory, "credential-secret")}, failure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SSL_CERT_FILE", test.file)
			t.Setenv("SSL_CERT_DIR", test.dir)
			config, err := (UV{}).tlsConfig(test.args)
			if (err != nil) != test.failure {
				t.Fatalf("error=%v", err)
			}
			if !test.failure && len(config.RootCAs.Subjects()) != test.want {
				t.Fatalf("roots=%d, want %d", len(config.RootCAs.Subjects()), test.want)
			}
		})
	}
}
