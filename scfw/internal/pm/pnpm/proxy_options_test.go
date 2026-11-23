// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"crypto/tls"
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
	if options.UpstreamTLS == nil {
		t.Fatal("upstream TLS configuration missing")
	}
	return verifiesTLSRoots(t, options.UpstreamTLS)
}

// verifiesTLSRoots reports whether a TLS configuration's roots trust the
// registry.test leaf certificate.
func verifiesTLSRoots(t *testing.T, config *tls.Config) bool {
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
	_, err = leaf.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: "registry.test"})
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
		{"empty ca option", []string{"--config.ca=", "add", "x"}, func(*testing.T, pnpmLayout) {}, false},
		{"empty npmrc ca", []string{"add", "x"}, func(t *testing.T, l pnpmLayout) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/empty-ca.npmrc")
		}, false},
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

// As in npm, a readable cafile or else a non-empty ca replaces the default
// roots; unlike npm, pnpm keeps NODE_EXTRA_CA_CERTS additive with a CA file.
// The Git bundle is appended regardless.
func TestProxyOptionsReplacesRootsLikePnpm(t *testing.T) {
	const registry, other = "registry", "other"
	pems := map[string]string{}
	for name, file := range map[string]string{registry: "registry-ca.pem", other: "scfw-ca.pem"} {
		data, err := os.ReadFile(filepath.Join(testdataDir, "tls", file))
		if err != nil {
			t.Fatal(err)
		}
		pems[name] = string(data)
	}
	poolOf := func(t *testing.T, names ...string) *x509.CertPool {
		t.Helper()
		pool := x509.NewCertPool()
		for _, name := range names {
			if !pool.AppendCertsFromPEM([]byte(pems[name])) {
				t.Fatalf("no certificate in %s", name)
			}
		}
		return pool
	}
	for _, test := range []struct {
		name    string
		command []string
		prepare func(t *testing.T, l pnpmLayout, registryPath, otherPath string)
		want    []string
	}{
		{"cafile only", []string{"add", "x"}, func(t *testing.T, l pnpmLayout, registryPath, _ string) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", registryPath)
		}, []string{registry}},
		{"ca only", []string{"--config.ca=" + pems[registry], "add", "x"}, func(*testing.T, pnpmLayout, string, string) {}, []string{registry}},
		{"readable cafile beats ca", []string{"--config.ca=" + pems[other], "add", "x"}, func(t *testing.T, l pnpmLayout, registryPath, _ string) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", registryPath)
		}, []string{registry}},
		{"missing cafile falls back to ca", []string{"--config.ca=" + pems[registry], "add", "x"}, func(t *testing.T, l pnpmLayout, _, _ string) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", filepath.Join(t.TempDir(), "missing.pem"))
		}, []string{registry}},
		{"empty cafile falls back to ca", []string{"--config.ca=" + pems[registry], "add", "x"}, func(t *testing.T, l pnpmLayout, _, _ string) {
			empty := filepath.Join(t.TempDir(), "empty.pem")
			if err := os.WriteFile(empty, nil, 0600); err != nil {
				t.Fatal(err)
			}
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", empty)
		}, []string{registry}},
		{"NODE_EXTRA_CA_CERTS stays additive", []string{"add", "x"}, func(t *testing.T, l pnpmLayout, registryPath, otherPath string) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", registryPath)
			t.Setenv("NODE_EXTRA_CA_CERTS", otherPath)
		}, []string{registry, other}},
		{"GIT_SSL_CAINFO is appended", []string{"add", "x"}, func(t *testing.T, l pnpmLayout, registryPath, otherPath string) {
			writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/cafile.npmrc.tmpl", registryPath)
			t.Setenv("GIT_SSL_CAINFO", otherPath)
		}, []string{registry, other}},
	} {
		for major, version := range pnpmVersions {
			layout := newPnpmWorkspace(t)
			paths := map[string]string{registry: filepath.Join(t.TempDir(), "registry.pem"), other: filepath.Join(t.TempDir(), "other.pem")}
			for name, path := range paths {
				if err := os.WriteFile(path, []byte(pems[name]), 0600); err != nil {
					t.Fatal(err)
				}
			}
			test.prepare(t, layout, paths[registry], paths[other])
			options, err := fakePnpm(t, version).ProxyOptions(test.command)
			if err != nil {
				t.Fatalf("pnpm %d %s: %v", major, test.name, err)
			}
			if !options.UpstreamTLS.RootCAs.Equal(poolOf(t, test.want...)) {
				t.Errorf("pnpm %d %s: upstream roots differ from %v", major, test.name, test.want)
			}
		}
	}
}

// A per-registry CA applies only to its registry host, where it replaces the
// global CA; every other upstream host keeps the global trust.
func TestProxyOptionsRegistryCA(t *testing.T) {
	caPath := filepath.Join(testdataDir, "tls", "registry-ca.pem")
	otherPath := filepath.Join(testdataDir, "tls", "scfw-ca.pem")
	registry, other := &url.URL{Scheme: "https", Host: "registry.test", Path: "/x"}, &url.URL{Scheme: "https", Host: "other.test"}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	registryCAPool := x509.NewCertPool()
	if !registryCAPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no certificate in registry-ca.pem")
	}
	for major, version := range pnpmVersions {
		for _, test := range []struct {
			name    string
			command []string
			prepare func(t *testing.T, l pnpmLayout)
			verify  func(t *testing.T, options proxy.Options)
		}{
			{"scoped to its registry", []string{"add", "x"}, func(t *testing.T, l pnpmLayout) {
				writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/registry-cafile.npmrc.tmpl", caPath)
			}, func(t *testing.T, options proxy.Options) {
				route, err := options.RouteForRequest(proxy.Request{URL: *registry})
				if err != nil || route == nil {
					t.Fatalf("registry route missing (error %v)", err)
				}
				if !verifiesTLSRoots(t, route.TLS) {
					t.Error("registry route does not trust the registry CA")
				}
				if route, err = options.RouteForRequest(proxy.Request{URL: *other}); err != nil || route != nil {
					t.Errorf("another host must keep the global trust, got %v (error %v)", route, err)
				}
				if verifiesRegistry(t, options) {
					t.Error("registry CA applied to every upstream host")
				}
			}},
			{"replaces the global cafile", []string{"--config.cafile=" + otherPath, "add", "x"}, func(t *testing.T, l pnpmLayout) {
				writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/registry-cafile.npmrc.tmpl", caPath)
			}, func(t *testing.T, options proxy.Options) {
				route, err := options.RouteForRequest(proxy.Request{URL: *registry})
				if err != nil || route == nil {
					t.Fatalf("registry route missing (error %v)", err)
				}
				if !route.TLS.RootCAs.Equal(registryCAPool) {
					t.Error("registry route must trust only the registry CA, not the global one")
				}
				if verifiesRegistry(t, options) {
					t.Error("the registry CA must not leak into the global roots")
				}
			}},
			{"strict-ssl=false skips verification on the route", []string{"add", "x"}, func(t *testing.T, l pnpmLayout) {
				writePnpmFixture(t, filepath.Join(l.workspace, ".npmrc"), "npmrc/registry-cafile-strict-ssl.npmrc.tmpl", caPath)
			}, func(t *testing.T, options proxy.Options) {
				route, err := options.RouteForRequest(proxy.Request{URL: *registry})
				if err != nil || route == nil {
					t.Fatalf("registry route missing (error %v)", err)
				}
				if !route.TLS.InsecureSkipVerify {
					t.Error("strict-ssl=false must skip verification on the registry route")
				}
			}},
		} {
			layout := newPnpmWorkspace(t)
			test.prepare(t, layout)
			options, err := fakePnpm(t, version).ProxyOptions(test.command)
			if err != nil {
				t.Fatalf("pnpm %d %s: %v", major, test.name, err)
			}
			if options.RouteForRequest == nil {
				t.Fatalf("pnpm %d %s: per-registry routes missing", major, test.name)
			}
			test.verify(t, options)
		}
	}
}

// pnpmRegistryCA matches npm-style //host[:port]/ keys against a request.
func TestPnpmRegistryCASelection(t *testing.T) {
	cafile, inline := registryCA{Key: "//a.test/", CAFile: "/ca.pem"}, registryCA{Key: "//a.test/", CA: "pem"}
	for _, test := range []struct {
		name   string
		cas    []registryCA
		target string
		want   registryCA
		found  bool
	}{
		{"host", []registryCA{cafile}, "https://a.test/x", cafile, true},
		{"default port", []registryCA{cafile}, "https://a.test:443/x", cafile, true},
		{"explicit port match", []registryCA{{Key: "//a.test:8443/", CAFile: "/ca.pem"}}, "https://a.test:8443/x", registryCA{Key: "//a.test:8443/", CAFile: "/ca.pem"}, true},
		{"explicit port mismatch", []registryCA{{Key: "//a.test:8443/", CAFile: "/ca.pem"}}, "https://a.test/x", registryCA{}, false},
		{"http default port", []registryCA{cafile}, "http://a.test/x", cafile, true},
		{"http port mismatch", []registryCA{cafile}, "http://a.test:8080/x", registryCA{}, false},
		{"other host", []registryCA{cafile}, "https://b.test/x", registryCA{}, false},
		{"inline ca beats cafile", []registryCA{cafile, inline}, "https://a.test/x", inline, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			got, found := pnpmRegistryCA(test.cas, target)
			if found != test.found || got != test.want {
				t.Fatalf("match = %v %#v, want %v %#v", found, got, test.found, test.want)
			}
		})
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
