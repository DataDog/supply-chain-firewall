// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
)

func (s *Settings) trustMaterial(values map[string]string, verification string, explicit bool, paths []string, native bool) (*x509.CertPool, []string, error) {
	enabled, err := verificationEnabled(values, verification)
	if err != nil {
		return nil, nil, err
	}
	if !enabled {
		return x509.NewCertPool(), nil, nil
	}
	if explicit {
		return x509.NewCertPool(), paths, nil
	}
	if !native {
		return nil, append(paths, s.sslPaths...), nil
	}
	s.nativeRootsOnce.Do(func() { s.nativeRoots, s.nativeRootsErr = nativeSystemRoots() })
	return s.nativeRoots, nil, s.nativeRootsErr
}

// Git/libcurl uses its OS trust defaults, not Python's SSL_CERT_FILE/DIR.
// On Linux x509.SystemCertPool itself consults those environment variables, so
// read the standard distribution trust stores directly. Darwin uses the native
// platform store, where SystemCertPool does not apply these Unix overrides.
func nativeSystemRoots() (*x509.CertPool, error) {
	if runtime.GOOS != "linux" {
		return x509.SystemCertPool()
	}
	roots := x509.NewCertPool()
	for _, file := range []string{
		"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem",
	} {
		if contents, err := os.ReadFile(file); err == nil {
			roots.AppendCertsFromPEM(contents)
			break
		}
	}
	for _, directory := range []string{"/etc/ssl/certs", "/etc/pki/tls/certs"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := filepath.Join(directory, entry.Name())
			info, err := os.Stat(name)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if contents, err := os.ReadFile(name); err == nil {
				roots.AppendCertsFromPEM(contents)
			}
		}
	}
	return roots, nil
}
