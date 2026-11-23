// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

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

// tlsFixturePools loads the CA fixtures shared by the replaces-roots tests:
// pems maps "registry" to tls/registry-ca.pem and "other" to tls/scfw-ca.pem,
// and pool builds the exact root pool of the named fixtures' certificates.
func tlsFixturePools(t *testing.T) (pems map[string]string, pool func(t *testing.T, names ...string) *x509.CertPool) {
	t.Helper()
	load := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(testdataDir, "tls", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	pems = map[string]string{"registry": load("registry-ca.pem"), "other": load("scfw-ca.pem")}
	return pems, func(t *testing.T, names ...string) *x509.CertPool {
		t.Helper()
		certPool := x509.NewCertPool()
		for _, name := range names {
			if !certPool.AppendCertsFromPEM([]byte(pems[name])) {
				t.Fatalf("no certificate in %s", name)
			}
		}
		return certPool
	}
}

func TestClassicProxyOptionsTrust(t *testing.T) {
	caPath := filepath.Join(testdataDir, "tls", "registry-ca.pem")
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join("parent", "project")
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		trusted bool
	}{
		{"none", func(*testing.T, string) {}, false},
		{".yarnrc cafile", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, project, ".yarnrc"), "yarnrc/cafile.yarnrc.tmpl", caPath)
		}, true},
		{".npmrc cafile without a yarn cafile", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, project, ".npmrc"), "yarnrc/cafile.npmrc.tmpl", caPath)
		}, true},
		{"YARN_CA", func(t *testing.T, _ string) { t.Setenv("YARN_CA", string(caPEM)) }, true},
		{"NODE_EXTRA_CA_CERTS", func(t *testing.T, _ string) { t.Setenv("NODE_EXTRA_CA_CERTS", caPath) }, true},
		{"GIT_SSL_CAINFO", func(t *testing.T, _ string) { t.Setenv("GIT_SSL_CAINFO", caPath) }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			test.prepare(t, root)
			options, err := fakeYarn(t, "1.22.22").ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := verifiesRegistry(t, options); got != test.trusted {
				t.Fatalf("trusted = %v, want %v", got, test.trusted)
			}
		})
	}
}

// Yarn reads cafile relative to its own process directory, which for
// `yarn workspace` is the workspace SCFW launches the command in, and a
// leading ~/ is the home directory in every configuration file.
func TestClassicCAFileResolvesInTheYarnProcess(t *testing.T) {
	for _, test := range []struct {
		name    string
		files   map[string]string
		command []string
		trusted bool
	}{
		{"relative to the workspace", map[string]string{"parent/project/a/.yarnrc": "yarnrc/cafile.yarnrc.tmpl", "parent/project/a/ca.pem": ""},
			[]string{"workspace", "a", "add", "x"}, true},
		// sub is the project, so its .yarnrc applies, but the path is not
		// relative to it.
		{"--cwd does not move the base", map[string]string{
			"parent/project/sub/package.json": "workspaces/empty.json", "parent/project/sub/.yarnrc": "yarnrc/cafile.yarnrc.tmpl", "parent/project/sub/ca.pem": "",
		}, []string{"--cwd", "sub", "add", "x"}, false},
		{"--cwd reads the project's .yarnrc", map[string]string{
			"parent/project/sub/package.json": "workspaces/empty.json", "parent/project/sub/.yarnrc": "yarnrc/cafile.yarnrc.tmpl", "parent/project/ca.pem": "",
		}, []string{"--cwd", "sub", "add", "x"}, true},
		{".yarnrc expands ~/", map[string]string{"parent/project/.yarnrc": "yarnrc/cafile.yarnrc.tmpl", "home/ca.pem": ""},
			[]string{"add", "x"}, true},
		{".npmrc expands ~/", map[string]string{"parent/project/.npmrc": "yarnrc/cafile.npmrc.tmpl", "home/ca.pem": ""},
			[]string{"add", "x"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			project := filepath.Join(root, "parent", "project")
			writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root-array.json")
			writeYarnFixture(t, filepath.Join(project, "a", "package.json"), "workspaces/member.json.tmpl", "a")
			value := "ca.pem"
			if _, home := test.files["home/ca.pem"]; home {
				value = "~/ca.pem"
			}
			for path, fixture := range test.files {
				if fixture == "" {
					writeYarnFixture(t, filepath.Join(root, path), "tls/registry-ca.pem")
				} else {
					writeYarnFixture(t, filepath.Join(root, path), fixture, value)
				}
			}
			manager := fakeYarn(t, "1.22.22")
			options, err := manager.ProxyOptions(test.command)
			if err != nil {
				t.Fatal(err)
			}
			if got := verifiesRegistry(t, options); got != test.trusted {
				t.Fatalf("trusted = %v, want %v", got, test.trusted)
			}
			// The launched Yarn reads the same file from its directory.
			spec, err := manager.ProxyCommand(context.Background(), test.command, testClientConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			if dir := spec.Dir; test.command[0] == "workspace" && dir != filepath.Join(project, "a") {
				t.Fatalf("Dir = %q, want the workspace", dir)
			}
		})
	}
}

// As in Yarn Classic, a readable cafile, else a non-empty ca, replaces the
// default roots, which also drops NODE_EXTRA_CA_CERTS; the Git bundle is
// appended regardless.
func TestClassicProxyOptionsReplacesRoots(t *testing.T) {
	const registry, other = "registry", "other"
	pems, poolOf := tlsFixturePools(t)
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, root, registryPath, otherPath string)
		want    []string
	}{
		{"cafile only", func(t *testing.T, root, registryPath, _ string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/cafile.yarnrc.tmpl", registryPath)
		}, []string{registry}},
		{"ca only", func(t *testing.T, _, _, _ string) { t.Setenv("YARN_CA", pems[registry]) }, []string{registry}},
		{"readable cafile beats ca", func(t *testing.T, root, registryPath, _ string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/cafile.yarnrc.tmpl", registryPath)
			t.Setenv("YARN_CA", pems[other])
		}, []string{registry}},
		{"missing cafile falls back to ca", func(t *testing.T, root, _, _ string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/cafile.yarnrc.tmpl", filepath.Join(t.TempDir(), "missing.pem"))
			t.Setenv("YARN_CA", pems[registry])
		}, []string{registry}},
		{"cafile drops NODE_EXTRA_CA_CERTS", func(t *testing.T, root, registryPath, otherPath string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/cafile.yarnrc.tmpl", registryPath)
			t.Setenv("NODE_EXTRA_CA_CERTS", otherPath)
		}, []string{registry}},
		{"ca drops NODE_EXTRA_CA_CERTS", func(t *testing.T, _, _, otherPath string) {
			t.Setenv("YARN_CA", pems[registry])
			t.Setenv("NODE_EXTRA_CA_CERTS", otherPath)
		}, []string{registry}},
		{"GIT_SSL_CAINFO is still appended", func(t *testing.T, root, registryPath, otherPath string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/cafile.yarnrc.tmpl", registryPath)
			t.Setenv("GIT_SSL_CAINFO", otherPath)
		}, []string{registry, other}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			dir := t.TempDir()
			registryPath, otherPath := filepath.Join(dir, "registry.pem"), filepath.Join(dir, "other.pem")
			writeYarnFixture(t, registryPath, "tls/registry-ca.pem")
			writeYarnFixture(t, otherPath, "tls/scfw-ca.pem")
			test.prepare(t, root, registryPath, otherPath)
			options, err := fakeYarn(t, "1.22.22").ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !options.UpstreamTLS.RootCAs.Equal(poolOf(t, test.want...)) {
				t.Fatalf("upstream roots differ from %v", test.want)
			}
		})
	}
}

// Yarn treats an empty ca as unset, so Node keeps its default roots and the
// NODE_EXTRA_CA_CERTS bundle still applies.
func TestClassicProxyOptionsIgnoresEmptyCA(t *testing.T) {
	for _, test := range []struct {
		name    string
		project string
		fixture string
	}{
		{".yarnrc ca", ".yarnrc", "yarnrc/empty-ca.yarnrc"},
		{".npmrc ca", ".npmrc", "yarnrc/empty-ca.npmrc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			caPath := filepath.Join(t.TempDir(), "extra.pem")
			writeYarnFixture(t, caPath, "tls/registry-ca.pem")
			t.Setenv("NODE_EXTRA_CA_CERTS", caPath)
			writeYarnFixture(t, filepath.Join(root, "parent", "project", test.project), test.fixture)
			options, err := fakeYarn(t, "1.22.22").ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !verifiesRegistry(t, options) {
				t.Fatal("an empty ca replaced the default roots instead of being ignored")
			}
		})
	}
}

func TestClassicProxyOptionsStrictSSL(t *testing.T) {
	target := &url.URL{Scheme: "https", Host: "registry.test"}
	project := filepath.Join("parent", "project")
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		trusted bool
	}{
		{"default", func(*testing.T, string) {}, false},
		// Yarn's own strict-ssl default shadows npm's setting.
		{"npm_config_strict_ssl ignored", func(t *testing.T, _ string) { t.Setenv("npm_config_strict_ssl", "false") }, false},
		{".npmrc ignored", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, project, ".npmrc"), "yarnrc/strict-ssl.npmrc")
		}, false},
		{"YARN_STRICT_SSL", func(t *testing.T, _ string) { t.Setenv("YARN_STRICT_SSL", "false") }, true},
		{".yarnrc", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, project, ".yarnrc"), "yarnrc/strict-ssl.yarnrc")
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			test.prepare(t, root)
			options, err := fakeYarn(t, "1.22.22").ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := options.TrustURL(target); got != test.trusted {
				t.Fatalf("TrustURL = %v, want %v", got, test.trusted)
			}
		})
	}
}

func TestClassicNpmClassifierOptions(t *testing.T) {
	t.Run("defaults to the Yarn registry", func(t *testing.T) {
		isolateYarnEnvironment(t)
		options, err := fakeYarn(t, "1.22.22").NpmClassifierOptions([]string{"install"})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"https://registry.yarnpkg.com"}; !slices.Equal(options.RegistryURLs, want) {
			t.Fatalf("registries = %q, want %q", options.RegistryURLs, want)
		}
	})
	t.Run("configured and scoped registries", func(t *testing.T) {
		root := isolateYarnEnvironment(t)
		writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/registries.yarnrc")
		writeYarnFixture(t, filepath.Join(root, "parent", "project", ".npmrc"), "yarnrc/registries.npmrc")
		options, err := fakeYarn(t, "1.22.22").NpmClassifierOptions([]string{"install"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"https://art.test/api/npm/yarn/", "https://art.test/api/npm/npm/",
			"https://art.test/api/npm/corp/", "https://art.test/api/npm/lab/",
		}
		if !slices.Equal(options.RegistryURLs, want) {
			t.Fatalf("registries = %q, want %q", options.RegistryURLs, want)
		}
		if _, err := npmregistry.NewClassifier(options); err != nil {
			t.Fatalf("classifier rejected the registries: %v", err)
		}
	})
	t.Run("registry option", func(t *testing.T) {
		isolateYarnEnvironment(t)
		options, err := fakeYarn(t, "1.22.22").NpmClassifierOptions([]string{"add", "x", "--registry", "https://o.test/"})
		if err != nil || !slices.Equal(options.RegistryURLs, []string{"https://o.test/"}) {
			t.Fatalf("registries = %q (error %v)", options.RegistryURLs, err)
		}
	})
}

// Yarn proxies every host, including loopback ones, which Go's flattened proxy
// configuration would connect to directly.
func TestProxyOptionsRoutesLikeYarn(t *testing.T) {
	for _, test := range []struct {
		version, target, want string
		prepare               func(t *testing.T, root string)
	}{
		{"1.22.22", "https://localhost:8443/x", "http://corp:1", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://corp:1")
		}},
		{"1.22.22", "http://registry.test/x", "http://env:1", func(t *testing.T, _ string) { t.Setenv("HTTP_PROXY", "http://env:1") }},
		{"1.22.22", "https://registry.test/x", "", func(t *testing.T, _ string) {
			t.Setenv("HTTPS_PROXY", "http://env:1")
			t.Setenv("NO_PROXY", "registry.test")
		}},
		{"1.22.22", "https://sub.registry.test/x", "", func(t *testing.T, _ string) {
			t.Setenv("HTTPS_PROXY", "http://env:1")
			t.Setenv("NO_PROXY", ".registry.test")
		}},
		// NO_PROXY applies only to a scheme whose proxy came from the environment.
		{"1.22.22", "https://registry.test/x", "http://corp:1", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://corp:1")
			t.Setenv("HTTP_PROXY", "http://env:1")
			t.Setenv("NO_PROXY", "registry.test")
		}},
		{"1.22.22", "http://registry.test/x", "", func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://corp:1")
			t.Setenv("HTTP_PROXY", "http://env:1")
			t.Setenv("NO_PROXY", "registry.test")
		}},
		{"4.18.1", "https://127.0.0.1:8443/x", "http://corp:1", func(t *testing.T, _ string) { t.Setenv("YARN_HTTPS_PROXY", "http://corp:1") }},
		{"4.18.1", "http://registry.test/x", "", func(t *testing.T, _ string) { t.Setenv("YARN_HTTPS_PROXY", "http://corp:1") }},
	} {
		t.Run(test.version+" "+test.target, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			test.prepare(t, root)
			options, err := fakeYarn(t, test.version).ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			if options.ProxyForURL == nil {
				t.Fatal("ProxyForURL missing")
			}
			got, err := options.ProxyForURL(target)
			if err != nil || (got == nil) != (test.want == "") || (got != nil && got.String() != test.want) {
				t.Fatalf("proxy = %v (error %v), want %q", got, err, test.want)
			}
		})
	}
}
