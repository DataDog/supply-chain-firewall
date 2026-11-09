// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func testClientConfig(t *testing.T) (proxy.ClientConfig, string) {
	t.Helper()
	pem := readNpmFixture(t, "tls/scfw-ca.pem")
	path := filepath.Join(t.TempDir(), "ca.pem")
	writeNpmFixture(t, path, pem)
	return proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: path}, pem
}

func scfwFlags(config proxy.ClientConfig, pem string) []string {
	return []string{
		"--https-proxy=" + config.URL, "--proxy=" + config.URL, "--noproxy=scfw.invalid",
		"--cafile=" + config.CACertificatePath, "--ca=" + pem,
	}
}

func TestProxyCommandInsertsFlagsBeforeSeparator(t *testing.T) {
	config, pem := testClientConfig(t)
	command := []string{"exec", "--yes", "--package=x", "--", "node", "-e", "1"}
	original := slices.Clone(command)
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Concat([]string{"exec", "--yes", "--package=x"}, scfwFlags(config, pem), []string{"--", "node", "-e", "1"})
	if !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
	if !slices.Equal(command, original) {
		t.Fatalf("caller's command was mutated: %q", command)
	}
}

func TestProxyCommandAppendsFlagsWithoutSeparator(t *testing.T) {
	config, pem := testClientConfig(t)
	command := []string{"--prefix", "/p", "install", "left-pad"}
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Executable != "/bin/npm" {
		t.Fatalf("executable = %q", spec.Executable)
	}
	if want := slices.Concat(command, scfwFlags(config, pem)); !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
}

func TestProxyCommandDropsUserNoproxyOptions(t *testing.T) {
	config, pem := testClientConfig(t)
	command := []string{"install", "--noproxy=a.test", "x", "--noproxy", "b.test", "--", "--noproxy=c.test"}
	original := slices.Clone(command)
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Concat([]string{"install", "x"}, scfwFlags(config, pem), []string{"--", "--noproxy=c.test"})
	if !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
	if !slices.Equal(command, original) {
		t.Fatalf("caller's command was mutated: %q", command)
	}
	// The user's bypass list still shapes SCFW's own upstream routing.
	manager := isolatedNpm(t)
	t.Setenv("npm_config_https_proxy", "http://corp:1")
	result, err := manager.settings(command)
	if err != nil {
		t.Fatal(err)
	}
	if result.NoProxy != "a.test,b.test" {
		t.Fatalf("upstream noproxy = %q, want the user's entries", result.NoProxy)
	}
}

func TestProxyCommandDropsTrailingNoproxyWithoutValue(t *testing.T) {
	config, pem := testClientConfig(t)
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install", "--noproxy"}, config)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Concat([]string{"install"}, scfwFlags(config, pem)); !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
}

func TestProxyCommandRejectsUnreadableCACertificate(t *testing.T) {
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: filepath.Join(t.TempDir(), "missing-secret.pem")}
	_, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install"}, config)
	if err == nil || err.Error() != "read proxy CA certificate" {
		t.Fatalf("error = %v", err)
	}
}

func TestProxyCommandBundlesUserNodeExtraCACerts(t *testing.T) {
	config, pem := testClientConfig(t)
	userCA := "-----BEGIN CERTIFICATE-----\nuser\n-----END CERTIFICATE-----\n"
	userFile := filepath.Join(t.TempDir(), "corporate.pem")
	writeNpmFixture(t, userFile, userCA)
	t.Setenv("NODE_EXTRA_CA_CERTS", userFile)
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	bundle := spec.EnvOverrides["NODE_EXTRA_CA_CERTS"]
	if filepath.Dir(bundle) != filepath.Dir(config.CACertificatePath) || bundle == config.CACertificatePath {
		t.Fatalf("bundle %q must be a separate file in the per-run CA directory", bundle)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != userCA+"\n"+pem {
		t.Fatalf("bundle = %q", data)
	}
	if spec.EnvOverrides["npm_config_cafile"] != config.CACertificatePath || spec.EnvOverrides["GIT_SSL_CAINFO"] != config.CACertificatePath {
		t.Fatal("only NODE_EXTRA_CA_CERTS may point at the bundle")
	}
}

func TestProxyCommandIgnoresUnreadableNodeExtraCACerts(t *testing.T) {
	config, _ := testClientConfig(t)
	t.Setenv("NODE_EXTRA_CA_CERTS", filepath.Join(t.TempDir(), "missing.pem"))
	spec, err := Npm{executable: "/bin/npm"}.ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvOverrides["NODE_EXTRA_CA_CERTS"] != config.CACertificatePath {
		t.Fatalf("NODE_EXTRA_CA_CERTS = %q", spec.EnvOverrides["NODE_EXTRA_CA_CERTS"])
	}
}

func TestNpmBypasses(t *testing.T) {
	for _, test := range []struct {
		host, noProxy string
		bypass        bool
	}{
		{"registry.lab.test", "lab.test", true},
		{"registry.lab.test", ".lab.test", true},
		{"notlab.test", "lab.test", false},
		{"registry.lab.test", "*", false},
		{"registry.lab.test", "registry.lab.test:443", false},
		{"registry.lab.test", "REGISTRY.LAB.TEST", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"a.test", " a.test , b.test ", true},
		{"b.test", " a.test , b.test ", true},
		{"registry.lab.test", "", false},
	} {
		target := &url.URL{Scheme: "https", Host: test.host + ":443"}
		if got := npmBypasses(target, test.noProxy); got != test.bypass {
			t.Errorf("npmBypasses(%q, %q) = %v, want %v", test.host, test.noProxy, got, test.bypass)
		}
	}
}

func TestProxyOptionsRoutesLikeNpm(t *testing.T) {
	for _, test := range []struct {
		name   string
		env    [][2]string
		npmrc  string
		target string
		want   string
	}{
		{name: "https-proxy beats proxy", npmrc: "https-proxy=http://hp:1\nproxy=http://p:2\n", target: "https://registry.test/x", want: "http://hp:1"},
		{name: "HTTP_PROXY never serves https", env: [][2]string{{"HTTP_PROXY", "http://h:3"}}, target: "https://registry.test/x"},
		{name: "bare PROXY serves http", env: [][2]string{{"PROXY", "http://bare:4"}}, target: "http://registry.test/x", want: "http://bare:4"},
		{name: "config noproxy bypasses", npmrc: "https-proxy=http://hp:1\nnoproxy=a.test\n", env: [][2]string{{"NO_PROXY", "b.test"}}, target: "https://a.test/x"},
		{name: "environment noproxy also bypasses", npmrc: "https-proxy=http://hp:1\nnoproxy=a.test\n", env: [][2]string{{"NO_PROXY", "b.test"}}, target: "https://b.test/x"},
		{name: "unmatched host is proxied", npmrc: "https-proxy=http://hp:1\nnoproxy=lab.test\n", target: "https://notlab.test/x", want: "http://hp:1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			for _, pair := range test.env {
				t.Setenv(pair[0], pair[1])
			}
			writeNpmFixture(t, ".npmrc", test.npmrc)
			options, err := manager.ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if options.ProxyForURL == nil {
				t.Fatal("ProxyForURL must be set")
			}
			target, _ := url.Parse(test.target)
			proxyURL, err := options.ProxyForURL(target)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if proxyURL != nil {
				got = proxyURL.String()
			}
			if got != test.want {
				t.Fatalf("proxy for %s = %q, want %q", test.target, got, test.want)
			}
		})
	}
}

// verifiesRegistry reports whether the upstream TLS roots in options trust the
// registry.test leaf certificate.
func verifiesRegistry(t *testing.T, options proxy.Options, leafPEM string) bool {
	t.Helper()
	block, _ := pem.Decode([]byte(leafPEM))
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

func TestProxyOptionsCarriesNpmRegistryTrust(t *testing.T) {
	caPEM, leafPEM := readNpmFixture(t, "tls/registry-ca.pem"), readNpmFixture(t, "tls/registry-leaf.pem")
	inline, err := json.Marshal(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, caPath string)
		trusted bool
	}{
		{"none", func(*testing.T, string) {}, false},
		{"npmrc cafile", func(t *testing.T, caPath string) { writeNpmFixture(t, ".npmrc", "cafile="+caPath+"\n") }, true},
		{"npmrc cafile under home", func(t *testing.T, caPath string) {
			writeNpmFixture(t, filepath.Join(os.Getenv("HOME"), "ca.pem"), caPEM)
			writeNpmFixture(t, ".npmrc", "cafile=~/ca.pem\n")
		}, true},
		{"environment ca", func(t *testing.T, _ string) { t.Setenv("npm_config_ca", caPEM) }, true},
		{"npmrc inline ca array", func(t *testing.T, _ string) { writeNpmFixture(t, ".npmrc", "ca[]="+string(inline)+"\n") }, true},
		{"NODE_EXTRA_CA_CERTS", func(t *testing.T, caPath string) { t.Setenv("NODE_EXTRA_CA_CERTS", caPath) }, true},
		{"GIT_SSL_CAINFO", func(t *testing.T, caPath string) { t.Setenv("GIT_SSL_CAINFO", caPath) }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			caPath := filepath.Join(t.TempDir(), "registry-ca.pem")
			writeNpmFixture(t, caPath, caPEM)
			test.prepare(t, caPath)
			options, err := manager.ProxyOptions(nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := verifiesRegistry(t, options, leafPEM); got != test.trusted {
				t.Fatalf("trusted = %v, want %v", got, test.trusted)
			}
		})
	}
}

func TestProxyOptionsLoadsTrustLikeNpm(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-secret.pem")
	for _, test := range []struct {
		name     string
		prepare  func(t *testing.T)
		failures bool
	}{
		// npm ignores a missing cafile and Node one in NODE_EXTRA_CA_CERTS.
		{"missing cafile", func(t *testing.T) { writeNpmFixture(t, ".npmrc", "cafile="+missing+"\n") }, false},
		{"missing NODE_EXTRA_CA_CERTS", func(t *testing.T) { t.Setenv("NODE_EXTRA_CA_CERTS", missing) }, false},
		// Git fails without its configured CA bundle, so SCFW fails like pip.
		{"missing GIT_SSL_CAINFO", func(t *testing.T) { t.Setenv("GIT_SSL_CAINFO", missing) }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			test.prepare(t)
			_, err := manager.ProxyOptions(nil)
			if (err != nil) != test.failures || (err != nil && strings.Contains(err.Error(), "missing-secret")) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestProxyOptionsHonorsStrictSSLFalse(t *testing.T) {
	target := &url.URL{Scheme: "https", Host: "registry.test"}
	for _, test := range []struct {
		name    string
		npmrc   string
		args    []string
		trusted bool
	}{
		{name: "default"},
		{name: "npmrc", npmrc: "strict-ssl=false\n", trusted: true},
		{name: "option", args: []string{"install", "--no-strict-ssl"}, trusted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := isolatedNpm(t)
			writeNpmFixture(t, ".npmrc", test.npmrc)
			options, err := manager.ProxyOptions(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if options.TrustURL == nil || options.TrustURL(target) != test.trusted {
				t.Fatalf("TrustURL trusted = %v", options.TrustURL != nil && options.TrustURL(target))
			}
		})
	}
}

func realNpm(t *testing.T) Npm {
	t.Helper()
	executable, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm required for npm integration tests")
	}
	manager := isolatedNpm(t)
	manager.executable = executable
	t.Setenv("npm_config_cache", t.TempDir())
	t.Setenv("npm_config_update_notifier", "false")
	return manager
}

func TestNpmHelpRunsThroughProxy(t *testing.T) {
	manager := realNpm(t)
	for _, args := range [][]string{{"help"}, {"install", "--help"}, {"--version"}} {
		commandErr, setupErr := proxy.Run(context.Background(), proxy.Options{}, args, manager)
		if commandErr != nil || setupErr != nil {
			t.Fatalf("%q failed: command=%v setup=%v", args, commandErr, setupErr)
		}
	}
}

func TestNpmCommandFailureIsPreserved(t *testing.T) {
	manager := realNpm(t)
	commandErr, setupErr := proxy.Run(context.Background(), proxy.Options{}, []string{"not-a-command"}, manager)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	exitErr, ok := commandErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("command error = %v, want npm's exit status 1", commandErr)
	}
}

func TestProxyEnvironmentOverrides(t *testing.T) {
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: "/run/ca.pem"}
	got := proxyEnvironmentOverrides(nil, config, "PEM")
	want := map[string]string{
		"HTTP_PROXY": config.URL, "http_proxy": config.URL, "HTTPS_PROXY": config.URL, "https_proxy": config.URL,
		"ALL_PROXY": config.URL, "all_proxy": config.URL, "npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL,
		"NO_PROXY": "", "no_proxy": "", "npm_config_noproxy": "scfw.invalid",
		"npm_config_cafile": "/run/ca.pem", "NODE_EXTRA_CA_CERTS": "/run/ca.pem", "GIT_SSL_CAINFO": "/run/ca.pem",
		"npm_config_ca": "PEM",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("overrides = %v, want %v", got, want)
	}
}

func TestProxyEnvironmentOverridesCoverExistingVariants(t *testing.T) {
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: "/run/ca.pem"}
	environ := []string{
		"NPM_CONFIG_HTTPS_PROXY=http://corp", "npm_config_https-proxy=http://corp", "Npm_Config_Noproxy=x",
		"No_Proxy=x", "NPM_CONFIG_CA=pem", "Https_Proxy=http://corp", "NPM_CONFIG_REGISTRY=https://r",
	}
	got := proxyEnvironmentOverrides(environ, config, "PEM")
	for key, value := range map[string]string{
		"NPM_CONFIG_HTTPS_PROXY": config.URL, "npm_config_https-proxy": config.URL, "Npm_Config_Noproxy": "scfw.invalid",
		"No_Proxy": "", "NPM_CONFIG_CA": "PEM", "Https_Proxy": config.URL,
	} {
		if actual, found := got[key]; !found || actual != value {
			t.Errorf("%s = %q (present %v), want %q", key, actual, found, value)
		}
	}
	if _, found := got["NPM_CONFIG_REGISTRY"]; found {
		t.Error("unrelated npm configuration must not be overridden")
	}
}
