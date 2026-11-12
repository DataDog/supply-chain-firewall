// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

var pnpmVersions = map[int]string{10: "10.34.9", 11: "11.28.9", 12: "12.18.0"}

// verifiesRegistry reports whether the upstream TLS roots in options trust the
// registry.test leaf certificate.
func verifiesRegistry(t *testing.T, options proxy.Options) bool {
	t.Helper()
	leafPEM, err := os.ReadFile(filepath.Join(testdataDir, "tls", "registry-leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if options.UpstreamTLS == nil {
		t.Fatal("upstream TLS configuration missing")
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: options.UpstreamTLS.RootCAs, DNSName: "registry.test"})
	return err == nil
}

func TestProxyOptionsRouting(t *testing.T) {
	registry := &url.URL{Scheme: "https", Host: "registry.test", Path: "/x"}
	other := &url.URL{Scheme: "https", Host: "other.test"}
	for major, version := range pnpmVersions {
		layout := newPnpmWorkspace(t)
		options, err := fakePnpm(t, version).ProxyOptions([]string{"add", "x"})
		if err != nil {
			t.Fatal(err)
		}
		if upstream, err := options.ProxyForURL(other); err != nil || upstream != nil {
			t.Errorf("pnpm %d: without an upstream the connection is direct, got %v (error %v)", major, upstream, err)
		}
		writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/routing.npmrc")
		options, err = fakePnpm(t, version).ProxyOptions([]string{"add", "x"})
		if err != nil {
			t.Fatal(err)
		}
		if upstream, err := options.ProxyForURL(registry); err != nil || upstream != nil {
			t.Errorf("pnpm %d: no-proxy must bypass registry.test, got %v (error %v)", major, upstream, err)
		}
		if upstream, err := options.ProxyForURL(other); err != nil || upstream == nil || upstream.Host != "upstream.test:1" {
			t.Errorf("pnpm %d: other.test must use the upstream, got %v (error %v)", major, upstream, err)
		}
	}
	layout := newPnpmWorkspace(t)
	writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/noproxy-all.npmrc")
	options, err := fakePnpm(t, "10.34.9").ProxyOptions([]string{"add", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if upstream, err := options.ProxyForURL(other); err != nil || upstream != nil {
		t.Errorf("noproxy=true must bypass every host, got %v (error %v)", upstream, err)
	}
}

func TestProxyOptionsTrust(t *testing.T) {
	caPath := filepath.Join(testdataDir, "tls", "registry-ca.pem")
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		command []string
		prepare func(t *testing.T, l pnpmLayout)
		trusted bool
	}{
		{"none", []string{"add", "x"}, func(*testing.T, pnpmLayout) {}, false},
		{"npmrc cafile", []string{"add", "x"}, func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", caPath)
		}, true},
		{"inline ca", []string{"--config.ca=" + string(caPEM), "add", "x"}, func(*testing.T, pnpmLayout) {}, true},
		{"registry cafile", []string{"add", "x"}, func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/registry-cafile.npmrc.tmpl", caPath)
		}, true},
		{"NODE_EXTRA_CA_CERTS", []string{"add", "x"}, func(t *testing.T, _ pnpmLayout) { t.Setenv("NODE_EXTRA_CA_CERTS", caPath) }, true},
		{"GIT_SSL_CAINFO", []string{"add", "x"}, func(t *testing.T, _ pnpmLayout) { t.Setenv("GIT_SSL_CAINFO", caPath) }, true},
	} {
		for major, version := range pnpmVersions {
			layout := newPnpmWorkspace(t)
			test.prepare(t, layout)
			options, err := fakePnpm(t, version).ProxyOptions(test.command)
			if err != nil {
				t.Fatalf("pnpm %d %s: %v", major, test.name, err)
			}
			if got := verifiesRegistry(t, options); got != test.trusted {
				t.Errorf("pnpm %d %s: trusted = %v, want %v", major, test.name, got, test.trusted)
			}
		}
	}
}

func TestProxyOptionsStrictSSL(t *testing.T) {
	target := &url.URL{Scheme: "https", Host: "registry.test"}
	for major, version := range pnpmVersions {
		layout := newPnpmWorkspace(t)
		options, err := fakePnpm(t, version).ProxyOptions(nil)
		if err != nil || options.TrustURL(target) {
			t.Fatalf("pnpm %d: default must verify certificates (error %v)", major, err)
		}
		writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/strict-ssl.npmrc")
		if options, err = fakePnpm(t, version).ProxyOptions(nil); err != nil || !options.TrustURL(target) {
			t.Fatalf("pnpm %d: strict-ssl=false must skip verification (error %v)", major, err)
		}
	}
	for _, major := range []int{11, 12} {
		layout := newPnpmWorkspace(t)
		writePnpmFixture(t, filepath.Join(layout.workspace, "pnpm-workspace.yaml"), "workspace-yaml/setting.yaml.tmpl", "strictSsl", "false")
		if options, err := fakePnpm(t, pnpmVersions[major]).ProxyOptions(nil); err != nil || !options.TrustURL(target) {
			t.Fatalf("pnpm %d: strictSsl: false must skip verification (error %v)", major, err)
		}
	}
}

func TestNpmClassifierOptions(t *testing.T) {
	defaults := []string{"https://registry.npmjs.org/", "https://npm.jsr.io/"}
	for major, version := range pnpmVersions {
		layout := newPnpmWorkspace(t)
		options, err := fakePnpm(t, version).NpmClassifierOptions([]string{"add", "x"})
		if err != nil || !slices.Equal(options.RegistryURLs, defaults) {
			t.Errorf("pnpm %d: defaults = %v (error %v), want %v", major, options.RegistryURLs, err, defaults)
		}
		writePnpmFixture(t, filepath.Join(layout.workspace, ".npmrc"), "npmrc/registries.npmrc")
		options, err = fakePnpm(t, version).NpmClassifierOptions([]string{"add", "x"})
		want := []string{"https://r.test/", "https://a.test/", "https://npm.jsr.io/"}
		if err != nil || !slices.Equal(options.RegistryURLs, want) {
			t.Errorf("pnpm %d: registries = %v (error %v), want %v", major, options.RegistryURLs, err, want)
		}
	}
	for _, major := range []int{11, 12} {
		layout := newPnpmWorkspace(t)
		writePnpmFixture(t, filepath.Join(layout.workspace, "pnpm-workspace.yaml"), "workspace-yaml/registries.yaml")
		options, err := fakePnpm(t, pnpmVersions[major]).NpmClassifierOptions([]string{"add", "x"})
		if err != nil || !slices.Contains(options.RegistryURLs, "https://lab.test/") {
			t.Errorf("pnpm %d: workspace registries = %v (error %v)", major, options.RegistryURLs, err)
		}
	}
}
