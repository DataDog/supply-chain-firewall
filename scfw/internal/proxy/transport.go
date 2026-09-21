// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

func (config NPMConfig) transport() (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	// Match npm's explicit strict-ssl setting for the outbound connection npm
	// delegated to SCFW. The default remains certificate verification enabled.
	tlsConfig.InsecureSkipVerify = config.insecureSkipTLSVerify //nolint:gosec // explicit npm compatibility setting

	if len(config.caCertificates) > 0 || config.caFile != "" {
		roots := x509.NewCertPool()
		certificates := append([]string(nil), config.caCertificates...)
		if config.caFile != "" {
			contents, err := os.ReadFile(config.caFile)
			if err != nil {
				return nil, fmt.Errorf("read registry CA file %s: %w", config.caFile, err)
			}
			certificates = append(certificates, string(contents))
		}
		for _, certificate := range certificates {
			if strings.TrimSpace(certificate) != "" && !roots.AppendCertsFromPEM([]byte(certificate)) {
				return nil, errors.New("parse certificate from registry CA configuration")
			}
		}
		tlsConfig.RootCAs = roots
	}

	if config.clientCertificate != "" || config.clientKey != "" {
		if config.clientCertificate == "" || config.clientKey == "" {
			return nil, errors.New("npm client certificate and key must both be configured")
		}
		certificate, err := tls.X509KeyPair([]byte(config.clientCertificate), []byte(config.clientKey))
		if err != nil {
			return nil, fmt.Errorf("parse npm client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport.TLSClientConfig = tlsConfig

	if config.httpProxy != "" || config.httpsProxy != "" || len(config.noProxy) > 0 {
		proxyConfig := httpproxy.FromEnvironment()
		if config.httpProxy != "" {
			proxyConfig.HTTPProxy = config.httpProxy
		}
		if config.httpsProxy != "" {
			proxyConfig.HTTPSProxy = config.httpsProxy
		}
		if len(config.noProxy) > 0 {
			proxyConfig.NoProxy = strings.Join(config.noProxy, ",")
		}
		proxyForURL := proxyConfig.ProxyFunc()
		transport.Proxy = func(request *http.Request) (*url.URL, error) {
			return proxyForURL(request.URL)
		}
	}
	return transport, nil
}

func (config NPMConfig) scopedTransports(base *http.Transport) (map[string]http.RoundTripper, error) {
	transports := make(map[string]http.RoundTripper)
	for prefix, credentials := range config.credentials {
		if credentials.certificateFile == "" && credentials.keyFile == "" {
			continue
		}
		if credentials.certificateFile == "" || credentials.keyFile == "" {
			continue
		}
		certificatePEM, err := os.ReadFile(credentials.certificateFile)
		if err != nil {
			return nil, fmt.Errorf("read npm certfile %s: %w", credentials.certificateFile, err)
		}
		keyPEM, err := os.ReadFile(credentials.keyFile)
		if err != nil {
			return nil, fmt.Errorf("read npm keyfile %s: %w", credentials.keyFile, err)
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse npm client certificate for %s: %w", prefix, err)
		}
		transport := base.Clone()
		transport.TLSClientConfig = base.TLSClientConfig.Clone()
		transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
		transports[prefix] = transport
	}
	return transports, nil
}
