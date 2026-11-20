// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
)

func TestBerryProxyOptionsTrust(t *testing.T) {
	caPath := filepath.Join(testdataDir, "tls", "registry-ca.pem")
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		trusted bool
	}{
		{"none", func(*testing.T, string) {}, false},
		// A relative path resolves against the rc file that sets it, not the cwd.
		{"parent rc relative httpsCaFilePath", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, "parent", ".yarnrc.yml"), "yarnrc-yml/ca-file.yml")
			writeYarnFixture(t, filepath.Join(root, "parent", "certs", "registry-ca.pem"), "tls/registry-ca.pem")
		}, true},
		{"YARN_HTTPS_CA_FILE_PATH", func(t *testing.T, _ string) { t.Setenv("YARN_HTTPS_CA_FILE_PATH", caPath) }, true},
		{"NODE_EXTRA_CA_CERTS", func(t *testing.T, _ string) { t.Setenv("NODE_EXTRA_CA_CERTS", caPath) }, true},
		{"GIT_SSL_CAINFO", func(t *testing.T, _ string) { t.Setenv("GIT_SSL_CAINFO", caPath) }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			test.prepare(t, root)
			options, err := fakeYarn(t, "4.18.1").ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := verifiesRegistry(t, options); got != test.trusted {
				t.Fatalf("trusted = %v, want %v", got, test.trusted)
			}
		})
	}
}

// A httpsCaFilePath replaces the roots as the running Yarn 4 does: from
// 4.9.2, and at any version without an httpsProxy. Before 4.9.2 a proxied
// request keeps Node's roots, where NODE_EXTRA_CA_CERTS still applies.
func TestBerryProxyOptionsReplacesRoots(t *testing.T) {
	const registry, other = "registry", "other"
	_, poolOf := tlsFixturePools(t)
	replaces := func(t *testing.T, registryPath, otherPath string) {
		t.Helper()
		t.Setenv("YARN_HTTPS_CA_FILE_PATH", registryPath)
		t.Setenv("NODE_EXTRA_CA_CERTS", otherPath)
	}
	for _, test := range []struct {
		name    string
		version string
		prepare func(t *testing.T, root, registryPath, otherPath string)
		want    []string // nil: the registry leaf must still verify through Node's roots
		fails   bool
	}{
		{"4.18.1 replaces roots", "4.18.1", func(t *testing.T, _, registryPath, otherPath string) {
			replaces(t, registryPath, otherPath)
		}, []string{registry}, false},
		{"4.9.2 replaces roots", "4.9.2", func(t *testing.T, _, registryPath, otherPath string) {
			replaces(t, registryPath, otherPath)
		}, []string{registry}, false},
		{"4.9.1 without httpsProxy replaces roots", "4.9.1", func(t *testing.T, _, registryPath, otherPath string) {
			replaces(t, registryPath, otherPath)
		}, []string{registry}, false},
		{"4.0.2 without httpsProxy replaces roots", "4.0.2", func(t *testing.T, _, registryPath, otherPath string) {
			replaces(t, registryPath, otherPath)
		}, []string{registry}, false},
		// The CA file Yarn would drop is unrelated, so the registry leaf
		// verifying proves it was ignored and NODE_EXTRA_CA_CERTS applies.
		{"4.9.1 with httpsProxy keeps Node roots", "4.9.1", func(t *testing.T, root, registryPath, otherPath string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc.yml"), "yarnrc-yml/https-proxy.yml.tmpl", "http://corp:1")
			t.Setenv("YARN_HTTPS_CA_FILE_PATH", otherPath)
			t.Setenv("NODE_EXTRA_CA_CERTS", registryPath)
		}, nil, false},
		{"missing file fails setup", "4.18.1", func(t *testing.T, _, _, _ string) {
			t.Setenv("YARN_HTTPS_CA_FILE_PATH", filepath.Join(t.TempDir(), "missing.pem"))
		}, nil, true},
		{"GIT_SSL_CAINFO is still appended", "4.18.1", func(t *testing.T, _, registryPath, otherPath string) {
			t.Setenv("YARN_HTTPS_CA_FILE_PATH", registryPath)
			t.Setenv("GIT_SSL_CAINFO", otherPath)
		}, []string{registry, other}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			dir := t.TempDir()
			registryPath, otherPath := filepath.Join(dir, "registry.pem"), filepath.Join(dir, "other.pem")
			writeYarnFixture(t, registryPath, "tls/registry-ca.pem")
			writeYarnFixture(t, otherPath, "tls/scfw-ca.pem")
			test.prepare(t, root, registryPath, otherPath)
			options, err := fakeYarn(t, test.version).ProxyOptions(nil)
			if test.fails {
				if err == nil {
					t.Fatal("setup must fail on an unreadable httpsCaFilePath")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.want != nil {
				if !options.UpstreamTLS.RootCAs.Equal(poolOf(t, test.want...)) {
					t.Fatalf("upstream roots differ from %v", test.want)
				}
			} else if !verifiesRegistry(t, options) {
				t.Fatal("the registry leaf must verify through Node's roots and NODE_EXTRA_CA_CERTS")
			}
		})
	}
}

func TestBerryProxyOptionsStrictSSL(t *testing.T) {
	target := &url.URL{Scheme: "https", Host: "registry.test"}
	root := isolateYarnEnvironment(t)
	options, err := fakeYarn(t, "4.18.1").ProxyOptions(nil)
	if err != nil || options.TrustURL(target) {
		t.Fatalf("default must verify certificates (error %v)", err)
	}
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc.yml"), "yarnrc-yml/strict-ssl.yml")
	options, err = fakeYarn(t, "4.18.1").ProxyOptions(nil)
	if err != nil || !options.TrustURL(target) {
		t.Fatalf("enableStrictSsl: false must skip verification (error %v)", err)
	}
}

func TestBerryNpmClassifierOptions(t *testing.T) {
	t.Run("defaults to the Yarn registry", func(t *testing.T) {
		isolateYarnEnvironment(t)
		options, err := fakeYarn(t, "4.18.1").NpmClassifierOptions([]string{"install"})
		if err != nil || !slices.Equal(options.RegistryURLs, []string{"https://registry.yarnpkg.com"}) {
			t.Fatalf("registries = %q (error %v)", options.RegistryURLs, err)
		}
	})
	t.Run("configured, scoped, and per-registry settings", func(t *testing.T) {
		root := isolateYarnEnvironment(t)
		writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc.yml"), "yarnrc-yml/registries.yml")
		options, err := fakeYarn(t, "4.18.1").NpmClassifierOptions([]string{"install"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"https://art.test/api/npm/main/", "https://art.test/api/npm/corp/", "https://npm.corp.example/repo/"}
		if !slices.Equal(options.RegistryURLs, want) {
			t.Fatalf("registries = %q, want %q", options.RegistryURLs, want)
		}
		if _, err := npmregistry.NewClassifier(options); err != nil {
			t.Fatalf("classifier rejected the registries: %v", err)
		}
	})
}
