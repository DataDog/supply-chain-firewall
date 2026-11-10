// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
)

// TLSConfigOptions contains effective trust material resolved by an adapter.
// The proxy does not consult package-manager configuration or environment.
type TLSConfigOptions struct {
	// RootCAs selects the base trust store. Nil preserves the system-trust
	// default; an explicitly empty pool trusts no default certificates.
	RootCAs               *x509.CertPool
	CABundlePaths         []string
	ClientCertificatePath string
	// An empty key path uses ClientCertificatePath as a combined PEM file.
	ClientKeyPath string
}

// NewTLSConfig augments the supplied roots (system trust by default) with PEM files or CA directories and
// optionally loads a client certificate. Errors omit paths which could contain credentials.
func NewTLSConfig(options TLSConfigOptions) (*tls.Config, error) {
	roots := options.RootCAs
	if roots != nil {
		roots = roots.Clone()
	} else {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
	}
	for _, path := range options.CABundlePaths {
		if path == "" {
			continue
		}
		if !appendCAPath(roots, path) {
			return nil, errors.New("could not load proxy CA bundle")
		}
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if options.ClientCertificatePath != "" {
		key := options.ClientKeyPath
		if key == "" {
			key = options.ClientCertificatePath
		}
		certificate, err := tls.LoadX509KeyPair(options.ClientCertificatePath, key)
		if err != nil {
			return nil, errors.New("could not load proxy client certificate")
		}
		config.Certificates = []tls.Certificate{certificate}
	} else if options.ClientKeyPath != "" {
		return nil, errors.New("proxy client certificate is missing")
	}
	return config, nil
}

func appendCAPath(roots *x509.CertPool, path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		pem, err := os.ReadFile(path)
		return err == nil && roots.AppendCertsFromPEM(pem)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := filepath.Join(path, entry.Name())
		// Follow OpenSSL hash symlinks, while skipping subdirectories, broken
		// links, and special files such as FIFOs. Unrelated files are common
		// in system CA directories and do not invalidate the directory.
		info, err := os.Stat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if pem, err := os.ReadFile(name); err == nil {
			roots.AppendCertsFromPEM(pem)
		}
	}
	return true
}
