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

func TestTLSConfigTrustsInlinePEM(t *testing.T) {
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "trusted")
	}))
	defer registry.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})
	for _, test := range []struct {
		name    string
		options TLSConfigOptions
		trusted bool
	}{
		{"inline", TLSConfigOptions{CABundlePEM: [][]byte{nil, cert}}, true},
		{"none", TLSConfigOptions{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := NewTLSConfig(test.options)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{TLSClientConfig: config}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport}).Get(registry.URL)
			if err == nil {
				_ = response.Body.Close()
			}
			if trusted := err == nil; trusted != test.trusted {
				t.Fatalf("trusted=%v want %v (error=%v)", trusted, test.trusted, err)
			}
		})
	}
}

func TestTLSConfigAddsInlinePEMToExplicitRoots(t *testing.T) {
	inline, unrelated := newTestCertificateAuthority(t), newTestCertificateAuthority(t)
	config, err := NewTLSConfig(TLSConfigOptions{RootCAs: x509.NewCertPool(), CABundlePEM: [][]byte{inline.pem}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		ca   *certificateAuthority
		want bool
	}{{"inline certificate", inline, true}, {"unrelated certificate", unrelated, false}} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.ca.certificate.Verify(x509.VerifyOptions{Roots: config.RootCAs})
			if verified := err == nil; verified != test.want {
				t.Fatalf("verified=%v want %v (error=%v)", verified, test.want, err)
			}
		})
	}
}

func TestTLSConfigRejectsInlinePEMWithoutCertificates(t *testing.T) {
	config, err := NewTLSConfig(TLSConfigOptions{CABundlePEM: [][]byte{[]byte("not a pem")}})
	if err == nil || config != nil || err.Error() != "could not load proxy CA bundle" {
		t.Fatalf("config=%v error=%v", config, err)
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

func TestTLSConfigUsesExplicitRootsWithoutChangingTheCallerPool(t *testing.T) {
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer registry.Close()
	base := x509.NewCertPool()
	certificate := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := NewTLSConfig(TLSConfigOptions{RootCAs: base, CABundlePaths: []string{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Subjects()) != 0 {
		t.Fatal("the caller's root pool was mutated")
	}
	for _, test := range []struct {
		name    string
		roots   *x509.CertPool
		allowed bool
	}{{"selected CA", config.RootCAs, true}, {"empty pool", base, false}} {
		t.Run(test.name, func(t *testing.T) {
			tlsConfig, err := NewTLSConfig(TLSConfigOptions{RootCAs: test.roots})
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{TLSClientConfig: tlsConfig}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport}).Get(registry.URL)
			if response != nil {
				_ = response.Body.Close()
			}
			if (err == nil) != test.allowed {
				t.Fatalf("TLS error=%v, allowed=%v", err, test.allowed)
			}
		})
	}
}
