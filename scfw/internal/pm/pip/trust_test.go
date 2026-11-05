// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestPipTrustedHostsDoNotDisableVerificationGlobally(t *testing.T) {
	configuration := readPipFixture(t, "config/wildcard-trust.conf")
	manager := goDiscoveryPip(t)
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer registry.Close()
	target, _ := url.Parse(registry.URL)
	for _, test := range []struct {
		name, host                          string
		environment, configuration, allowed bool
	}{
		{name: "environment wildcard", host: "*", environment: true},
		{name: "argument wildcard", host: "*"},
		{name: "port wildcard", host: "*:" + target.Port()},
		{name: "configuration wildcard", configuration: true},
		{name: "exact host", host: target.Hostname(), allowed: true},
		{name: "exact host and port", host: target.Host, allowed: true},
		{name: "wrong port", host: target.Hostname() + ":1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []string{"download", "project"}
			switch {
			case test.configuration:
				path := filepath.Join(t.TempDir(), "pip.conf")
				writePipFixture(t, path, configuration)
				t.Setenv("PIP_CONFIG_FILE", path)
			case test.environment:
				t.Setenv("PIP_TRUSTED_HOST", test.host)
			default:
				args = append(args, "--trusted-host", test.host)
			}
			options, err := manager.ProxyOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			transport := proxy.NewTransport(options)
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport}).Get(registry.URL)
			if response != nil {
				_ = response.Body.Close()
			}
			if (err == nil) != test.allowed {
				t.Fatalf("self-signed registry allowed=%t, want %t: %v", err == nil, test.allowed, err)
			}
		})
	}
}

func TestPipTrustURLMatchesLiteralHosts(t *testing.T) {
	for _, test := range []struct {
		host, target string
		want         bool
	}{
		{"*", "https://registry.example/project", false},
		{"*:443", "https://registry.example:443/project", false},
		{"*.example", "https://registry.example/project", false},
		{"registry.example", "https://registry.example/project", true},
		{"REGISTRY.EXAMPLE", "https://registry.example:8443/project", true},
		{"registry.example", "https://sub.registry.example/project", false},
		{"registry.example:443", "https://registry.example:443/project", true},
		{"registry.example:443", "https://registry.example/project", false},
		{"registry.example:443", "https://registry.example:8443/project", false},
		{"registry.example:", "https://registry.example:8443/project", false},
		{"[::1]", "https://[::1]:8443/project", true},
		{"::1", "https://[::1]/project", true},
		{"[::1]:8443", "https://[::1]:8443/project", true},
		{"[::1]:8443", "https://[::1]:443/project", false},
		{"[::1]", "https://[::2]/project", false},
		{"https://registry.example", "https://registry.example/project", false},
	} {
		t.Run(test.host+" "+test.target, func(t *testing.T) {
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			if got := pipTrustURL([]string{test.host})(target); got != test.want {
				t.Fatalf("trusted=%t, want %t", got, test.want)
			}
		})
	}
	if pipTrustURL([]string{"*"})(nil) {
		t.Fatal("nil URL was trusted")
	}
}
