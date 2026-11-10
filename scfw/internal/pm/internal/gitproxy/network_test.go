// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func gitNetworkEnvironment(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git required")
	}
	for _, key := range []string{
		"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_CERT", "GIT_SSL_KEY", "GIT_SSL_NO_VERIFY",
		"GIT_PROXY_SSL_CAINFO", "GIT_PROXY_SSL_CERT", "GIT_PROXY_SSL_KEY", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
	} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	return t.TempDir()
}

func TestGitVerificationMatchesNativeBooleans(t *testing.T) {
	for _, key := range []string{"http.sslVerify", "http.proxySSLVerify"} {
		for _, value := range []string{"2", "-1", "0", "1", "true", "yes", "on", "false", "no", "off", ""} {
			t.Run(key+"/"+value, func(t *testing.T) {
				directory := gitNetworkEnvironment(t)
				t.Setenv("GIT_CONFIG_COUNT", "2")
				t.Setenv("GIT_CONFIG_KEY_0", key)
				t.Setenv("GIT_CONFIG_VALUE_0", value)
				t.Setenv("GIT_CONFIG_KEY_1", "http.proxy")
				t.Setenv("GIT_CONFIG_VALUE_1", "https://proxy.example:443")
				native, err := exec.Command("git", "config", "--type=bool", "--get", key).Output()
				if err != nil {
					t.Fatal(err)
				}
				enabled := strings.TrimSpace(string(native)) == "true"
				settings, err := Read(directory)
				if err != nil {
					t.Fatal(err)
				}
				target, _ := url.Parse("https://registry.example/repository")
				route, err := settings.Route(proxy.Request{URL: *target})
				if err != nil {
					t.Fatal(err)
				}
				config := route.TLS
				if key == "http.proxySSLVerify" {
					config = route.ProxyTLS
				}
				if config.InsecureSkipVerify == enabled {
					t.Fatalf("Git verification=%v, shared InsecureSkipVerify=%v", enabled, config.InsecureSkipVerify)
				}
			})
		}
	}
}

func TestGitVerificationRejectsMalformedValues(t *testing.T) {
	for _, key := range []string{"http.sslVerify", "http.proxySSLVerify"} {
		t.Run(key, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			t.Setenv("GIT_CONFIG_COUNT", "2")
			t.Setenv("GIT_CONFIG_KEY_0", key)
			t.Setenv("GIT_CONFIG_VALUE_0", "credential-secret")
			t.Setenv("GIT_CONFIG_KEY_1", "http.proxy")
			t.Setenv("GIT_CONFIG_VALUE_1", "https://proxy.example:443")
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse("https://registry.example/repository")
			if _, err := settings.Route(proxy.Request{URL: *target}); err == nil || strings.Contains(err.Error(), "credential-secret") {
				t.Fatalf("missing or unsafe verification error: %v", err)
			}
		})
	}
}

func TestGitVerificationPreservesURLScopesAndSnapshot(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	t.Setenv("GIT_CONFIG_COUNT", "4")
	for index, key := range []string{"http.sslVerify", "http.proxySSLVerify", "http.https://specific.example/.sslVerify", "http.https://specific.example/.proxySSLVerify"} {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), key)
		value := "2"
		if index >= 2 {
			value = "0"
		}
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), value)
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_VALUE_0", "credential-secret")
	for _, test := range []struct{ address, want string }{{"https://elsewhere.example/repo", "true"}, {"https://specific.example/repo", "false"}} {
		target, _ := url.Parse(test.address)
		values, err := settings.Values(target)
		if err != nil || values["sslverify"] != test.want || values["proxysslverify"] != test.want {
			t.Fatalf("scoped verification=%v: %v", values, err)
		}
	}
}

func TestGitFileVerificationPreservesImplicitBooleans(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	fixture, err := filepath.Abs("testdata/verification-implicit.conf")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", fixture)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http.sslVerify")
	t.Setenv("GIT_CONFIG_VALUE_0", "0")
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://registry.example/repo")
	values, err := settings.FileValues(target)
	if err != nil || values["sslverify"] != "true" || values["proxysslverify"] != "true" {
		t.Fatalf("file-only implicit values=%v: %v", values, err)
	}
}

func TestGitCASelectionMatchesNativeGit(t *testing.T) {
	for _, source := range []string{"environment", "configuration"} {
		t.Run(source, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); http.NotFound(w, r) }))
			defer server.Close()
			certificate := filepath.Join(directory, "git-ca.pem")
			if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSL_CERT_FILE", filepath.Join(directory, "unused-credential-secret.pem"))
			if source == "environment" {
				t.Setenv("GIT_SSL_CAINFO", certificate)
			} else {
				t.Setenv("GIT_CONFIG_COUNT", "1")
				t.Setenv("GIT_CONFIG_KEY_0", "http.sslCAInfo")
				t.Setenv("GIT_CONFIG_VALUE_0", certificate)
			}
			command := exec.Command("git", "ls-remote", server.URL+"/repo")
			command.Dir = directory
			_ = command.Run() // A 404 proves Git got past certificate verification.
			if requests.Load() == 0 {
				t.Fatal("native Git could not connect with its selected CA")
			}
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			transport := proxy.NewTransport(proxy.Options{RouteForRequest: settings.Route})
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport}).Get(server.URL + "/repo")
			if err != nil {
				t.Fatalf("native Git connected, shared routing failed: %v", err)
			}
			_ = response.Body.Close()
		})
	}
}

func TestGitLoadsOnlySelectedTLSMaterial(t *testing.T) {
	for _, test := range []struct {
		name, target, upstream string
		failure                bool
	}{
		{name: "plain direct", target: "http://registry.example/repo"},
		{name: "plain proxy", target: "http://registry.example/repo", upstream: "http://proxy.example:8080"},
		{name: "selected origin", target: "https://registry.example/repo", failure: true},
		{name: "selected proxy", target: "http://registry.example/repo", upstream: "https://proxy.example:443", failure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			t.Setenv("GIT_SSL_CAINFO", filepath.Join(directory, "origin-credential-secret.pem"))
			t.Setenv("GIT_PROXY_SSL_CAINFO", filepath.Join(directory, "proxy-credential-secret.pem"))
			t.Setenv("https_proxy", test.upstream)
			t.Setenv("http_proxy", test.upstream)
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(test.target)
			route, err := settings.Route(proxy.Request{URL: *target})
			if test.failure {
				if err == nil || strings.Contains(err.Error(), "credential-secret") {
					t.Fatalf("selected TLS material: %v", err)
				}
			} else if err != nil || route.TLS != nil || route.ProxyTLS != nil {
				t.Fatalf("unused TLS material was loaded: route=%+v error=%v", route, err)
			}
		})
	}
}

func TestGitTLSConnectionsUseIndependentSelectedRoots(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var roots [2]string
	var pools [2]*x509.CertPool
	for index := range roots {
		server, err := proxy.Start(context.Background(), proxy.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		roots[index] = server.ClientConfig().CACertificatePath
		data, err := os.ReadFile(roots[index])
		if err != nil {
			t.Fatal(err)
		}
		pools[index] = x509.NewCertPool()
		if !pools[index].AppendCertsFromPEM(data) {
			t.Fatal("invalid fixture CA")
		}
	}
	missing := filepath.Join(directory, "unused-credential-secret.pem")
	for _, test := range []struct {
		name, target, upstream, origin, proxy string
		wantOrigin, wantProxy                 bool
	}{
		{"both TLS connections", "https://registry.example/repo", "https://proxy.example:443", roots[0], roots[1], true, true},
		{"proxy TLS only", "http://registry.example/repo", "https://proxy.example:443", missing, roots[1], false, true},
		{"origin TLS only", "https://registry.example/repo", "http://proxy.example:8080", roots[0], missing, true, false},
		{"direct TLS", "https://registry.example/repo", "", roots[0], missing, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SSL_CERT_FILE", missing)
			t.Setenv("GIT_SSL_CAINFO", test.origin)
			t.Setenv("GIT_PROXY_SSL_CAINFO", test.proxy)
			t.Setenv("http_proxy", test.upstream)
			t.Setenv("https_proxy", test.upstream)
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(test.target)
			route, err := settings.Route(proxy.Request{URL: *target})
			if err != nil {
				t.Fatal(err)
			}
			if (route.TLS != nil) != test.wantOrigin || (route.ProxyTLS != nil) != test.wantProxy {
				t.Fatal("TLS settings loaded for the wrong connection")
			}
			if route.TLS != nil && !route.TLS.RootCAs.Equal(pools[0]) {
				t.Fatal("destination CA roots were widened or replaced")
			}
			if route.ProxyTLS != nil && !route.ProxyTLS.RootCAs.Equal(pools[1]) {
				t.Fatal("HTTPS proxy CA roots were widened or replaced")
			}
		})
	}
}

func gitTLSOrigin(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); http.NotFound(w, r) }))
	t.Cleanup(server.Close)
	return server
}
