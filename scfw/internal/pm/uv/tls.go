// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// Use system trust by default, as in the shared proxy. Explicit uv CA sources
// replace it; uv's native-TLS options remain the child process's responsibility.
func (uv UV) tlsConfig(command []string) (*tls.Config, error) {
	options := uv.parseOptions(command)
	working, err := uv.workingDirectory(command)
	if err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	var certificate string
	explicit := false
	for _, option := range options.options {
		if option.name == "cert" {
			certificate, explicit = option.value, true
		}
	}
	if explicit {
		// --cert replaces both environment sources and rejects invalid files.
		roots = x509.NewCertPool()
		if !loadCertificateFile(roots, resolvePath(working, certificate)) {
			return nil, errors.New("could not load uv --cert CA bundle")
		}
	} else if os.Getenv("SSL_CERT_FILE") != "" || os.Getenv("SSL_CERT_DIR") != "" {
		// A configured source replaces defaults even if missing or empty.
		roots = x509.NewCertPool()
		if path := os.Getenv("SSL_CERT_FILE"); path != "" {
			loadCertificateFile(roots, resolvePath(working, path))
		}
		for _, path := range filepath.SplitList(os.Getenv("SSL_CERT_DIR")) {
			if path == "" {
				continue
			}
			entries, err := os.ReadDir(resolvePath(working, path))
			if err != nil {
				continue
			}
			for _, entry := range entries {
				loadCertificateFile(roots, filepath.Join(resolvePath(working, path), entry.Name()))
			}
		}
	}
	config, err := proxy.NewTLSConfig(proxy.TLSConfigOptions{RootCAs: roots})
	if err != nil {
		return nil, err
	}
	if path := os.Getenv("SSL_CLIENT_CERT"); path != "" {
		certificate, err := tls.LoadX509KeyPair(resolvePath(working, path), resolvePath(working, path))
		if err == nil {
			config.Certificates = []tls.Certificate{certificate}
		} else {
			// uv also ignores invalid mTLS identities. Do not log credential paths.
			slog.Warn("ignoring invalid uv client certificate")
		}
	}
	return config, nil
}

func loadCertificateFile(roots *x509.CertPool, path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	content, err := os.ReadFile(path)
	return err == nil && roots.AppendCertsFromPEM(content)
}
