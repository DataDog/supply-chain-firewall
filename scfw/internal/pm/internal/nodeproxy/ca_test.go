// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"os"
	"path/filepath"
	"testing"
)

const testCAPEM = "-----BEGIN CERTIFICATE-----\nscfw\n-----END CERTIFICATE-----\n"

func testCAPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte(testCAPEM), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNodeExtraCACertsBundlesUserCertificates(t *testing.T) {
	caPath := testCAPath(t)
	userCA := "-----BEGIN CERTIFICATE-----\nuser\n-----END CERTIFICATE-----\n"
	userFile := filepath.Join(t.TempDir(), "corporate.pem")
	if err := os.WriteFile(userFile, []byte(userCA), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE_EXTRA_CA_CERTS", userFile)
	bundle, err := NodeExtraCACerts(caPath, []byte(testCAPEM))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(bundle) != filepath.Dir(caPath) || bundle == caPath {
		t.Fatalf("bundle %q must be a separate file in the per-run CA directory", bundle)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != userCA+"\n"+testCAPEM {
		t.Fatalf("bundle = %q", data)
	}
	if info, err := os.Stat(bundle); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("bundle mode = %v (error %v)", info.Mode().Perm(), err)
	}
}

func TestNodeExtraCACertsWithoutUserBundle(t *testing.T) {
	caPath := testCAPath(t)
	t.Setenv("NODE_EXTRA_CA_CERTS", "")
	got, err := NodeExtraCACerts(caPath, []byte(testCAPEM))
	if err != nil || got != caPath {
		t.Fatalf("path = %q (error %v), want the CA itself", got, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(caPath)); len(entries) != 1 {
		t.Fatalf("no bundle may be written: %v", entries)
	}
}

func TestNodeExtraCACertsIgnoresMissingUserBundle(t *testing.T) {
	caPath := testCAPath(t)
	t.Setenv("NODE_EXTRA_CA_CERTS", filepath.Join(t.TempDir(), "missing.pem"))
	got, err := NodeExtraCACerts(caPath, []byte(testCAPEM))
	if err != nil || got != caPath {
		t.Fatalf("path = %q (error %v), want the CA itself", got, err)
	}
}
