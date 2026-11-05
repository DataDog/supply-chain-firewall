// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSConfigLoadsTrustAndClientCertificates(t *testing.T) {
	registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "client certificate missing", 401)
			return
		}
		_, _ = io.WriteString(w, "authenticated")
	}))
	registry.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	registry.StartTLS()
	defer registry.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})
	privateKey, err := x509.MarshalPKCS8PrivateKey(registry.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
	directory := t.TempDir()
	certPath, keyPath, combined := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem"), filepath.Join(directory, "combined.pem")
	for path, data := range map[string][]byte{certPath: cert, keyPath: key, combined: append(append([]byte{}, cert...), key...)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caDirectory := t.TempDir()
	if err := os.Symlink(certPath, filepath.Join(caDirectory, "01234567.0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(caDirectory, "missing"), filepath.Join(caDirectory, "broken.0")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDirectory, "unrelated.json"), []byte(readProxyFixture(t, "package.json")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(caDirectory, "subdirectory"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, options := range []TLSConfigOptions{
		{CABundlePaths: []string{certPath}, ClientCertificatePath: certPath, ClientKeyPath: keyPath},
		{CABundlePaths: []string{"", certPath}, ClientCertificatePath: combined},
		{CABundlePaths: []string{caDirectory}, ClientCertificatePath: combined},
	} {
		config, err := NewTLSConfig(options)
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{TLSClientConfig: config}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport}
		response, err := client.Get(registry.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != "authenticated" {
			t.Fatalf("body=%q error=%v", body, err)
		}
	}
}

func TestTLSConfigAcceptsEmptyCADirectory(t *testing.T) {
	if _, err := NewTLSConfig(TLSConfigOptions{CABundlePaths: []string{t.TempDir()}}); err != nil {
		t.Fatalf("an empty CA directory must not fail configuration: %v", err)
	}
}

func TestTLSConfigErrorsDoNotExposePaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "credential-secret.pem")
	for _, options := range []TLSConfigOptions{{CABundlePaths: []string{missing}}, {ClientCertificatePath: missing}, {ClientKeyPath: missing}} {
		config, err := NewTLSConfig(options)
		if err == nil || config != nil || strings.Contains(err.Error(), "credential-secret") {
			t.Fatalf("config=%v error=%v", config, err)
		}
	}
}
