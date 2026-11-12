// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func configPool(t *testing.T, ca []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	return pool
}

func poetryInvocationConfig(t *testing.T, clients ...map[string]proxy.Options) proxy.ClientConfig {
	t.Helper()
	start := func(options proxy.Options) proxy.ClientConfig {
		server, err := proxy.Start(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		return server.ClientConfig()
	}
	config := start(proxy.Options{})
	additional := map[string]proxy.Options{poetryNativeGitClient: {}}
	if len(clients) > 0 {
		additional = clients[0]
	}
	config.AdditionalClients = map[string]proxy.ClientConfig{}
	for name, options := range additional {
		config.AdditionalClients[name] = start(options)
	}
	return config
}

func isolatedPoetryProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, ".config"))
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("POETRY_CONFIG_DIR", root)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "absent-gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	for _, name := range []string{"GIT_CONFIG_PARAMETERS", "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "no_proxy", "NO_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_CERT", "GIT_SSL_KEY", "SSL_CERT_FILE", "SSL_CERT_DIR", "POETRY_SYSTEM_GIT_CLIENT", "POETRY_CERTIFICATES_PRIVATE_CERT", "POETRY_CERTIFICATES_PRIVATE_VERIFY", "POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	poetrySettingsFixture(t, "proxy-project.toml", filepath.Join(root, "pyproject.toml"))
	return root
}

func TestPoetrySymlinkProjectPreservesVerification(t *testing.T) {
	root := isolatedPoetryProject(t)
	physical := filepath.Join(root, "real")
	work := filepath.Join(physical, "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(work, link); err != nil {
		t.Fatal(err)
	}
	poetrySettingsFixture(t, "proxy-project.toml", filepath.Join(physical, "pyproject.toml"))
	paths := map[string][]byte{}
	paths[filepath.Join(root, "poetry.toml")] = poetrySettingsFixture(t, "disabled-private-trust.toml", filepath.Join(root, "poetry.toml"))
	paths[filepath.Join(physical, "poetry.toml")] = poetrySettingsFixture(t, "local-repository-trust.toml", filepath.Join(physical, "poetry.toml"))
	target, err := url.Parse("https://index.example/simple/project/")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-C", link, "-P", "..", "install"},
		{"-C", link + "/..", "install"},
		{"-P", link + "/..", "install"},
	} {
		manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
		options, err := manager.ProxyOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		route, err := options.RouteForRequest(proxy.Request{URL: *target})
		if err != nil || route.TLS.InsecureSkipVerify {
			t.Fatalf("selected the wrong project's TLS verification: %v", err)
		}
	}
	for path, before := range paths {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatal("project TLS configuration changed")
		}
	}
}

func TestPoetryGitListenersKeepRoutingAndTrustSeparate(t *testing.T) {
	root := isolatedPoetryProject(t)
	t.Setenv("https_proxy", "http://environment-proxy.example:8080")
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "http.https://git.example/.proxy")
	t.Setenv("GIT_CONFIG_VALUE_0", "http://native-proxy.example:8080")
	t.Setenv("GIT_CONFIG_KEY_1", "http.userAgent")
	t.Setenv("GIT_CONFIG_VALUE_1", "custom-agent")
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}, proxyState: &poetryProxyState{}}
	args := []string{"--directory", root, "install"}
	options, err := manager.ProxyOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://git.example/repo/info/refs?service=git-upload-pack")
	request := proxy.Request{URL: *target, Header: http.Header{"User-Agent": {"git-dulwich/0.24"}}}
	bundled, err := options.RouteForRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", "custom-agent")
	var native *proxy.OutboundRoute
	for name, client := range options.AdditionalClients {
		if name == poetryNativeGitClient {
			continue
		}
		native, err = client.RouteForRequest(request)
		if err != nil {
			t.Fatal(err)
		}
	}
	if native == nil {
		t.Fatal("missing URL-scoped native Git listener")
	}
	if bundled.ProxyURL == nil || bundled.ProxyURL.String() != "http://environment-proxy.example:8080" || native.ProxyURL == nil || native.ProxyURL.String() != "http://native-proxy.example:8080" {
		t.Fatalf("Git clients did not retain their distinct original routes: %v / %v", bundled.ProxyURL, native.ProxyURL)
	}
	config := poetryInvocationConfig(t, options.AdditionalClients)
	spec, err := manager.ProxyCommand(context.Background(), args, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvOverrides["https_proxy"] != config.URL {
		t.Fatal("Dulwich lost the process listener")
	}
	count, err := strconv.Atoi(spec.EnvOverrides["GIT_CONFIG_COUNT"])
	if err != nil {
		t.Fatal(err)
	}
	for index := 2; index < count; index++ {
		key := spec.EnvOverrides["GIT_CONFIG_KEY_"+strconv.Itoa(index)]
		if strings.HasSuffix(key, ".proxy") {
			assigned := false
			for _, client := range config.AdditionalClients {
				if spec.EnvOverrides["GIT_CONFIG_VALUE_"+strconv.Itoa(index)] == client.URL {
					assigned = true
				}
			}
			if !assigned {
				t.Fatal("native Git was not assigned an invocation configuration listener")
			}
		}
	}
	bundle, err := os.ReadFile(spec.EnvOverrides["GIT_SSL_CAINFO"])
	if err != nil {
		t.Fatal(err)
	}
	clients := []proxy.ClientConfig{config}
	for _, client := range config.AdditionalClients {
		clients = append(clients, client)
	}
	for _, client := range clients {
		ca, err := os.ReadFile(client.CACertificatePath)
		if err != nil || !bytes.Contains(bundle, ca) {
			t.Fatal("shared Git trust does not contain both invocation CAs")
		}
	}
	delete(config.AdditionalClients, poetryNativeGitClient)
	if _, err := manager.ProxyCommand(context.Background(), args, config); err == nil {
		t.Fatal("missing native listener was silently accepted")
	}
}

func TestPoetryRelativeRequestsTrust(t *testing.T) {
	root := isolatedPoetryProject(t)
	config := poetryInvocationConfig(t)
	ca, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	// Environment paths remain literal even when they look like Poetry placeholders.
	filename := "literal-{cache-dir}.pem"
	if err := os.WriteFile(filepath.Join(root, filename), ca, 0600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	poetrySettingsFixture(t, "proxy-project.toml", filepath.Join(project, "pyproject.toml"))
	t.Chdir(t.TempDir())
	for _, version := range []pm.Version{{Major: 2}, {Major: 2, Minor: 5}} {
		for _, key := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
			for _, path := range []string{filename, ".", filepath.Join(root, filename)} {
				t.Run(version.String()+"/"+key+"/"+path, func(t *testing.T) {
					t.Setenv(key, path)
					if key == "REQUESTS_CA_BUNDLE" {
						t.Setenv("CURL_CA_BUNDLE", "/ignored/missing.pem")
					}
					manager := Poetry{version: version}
					options, err := manager.ProxyOptions([]string{"--directory", root, "--project", "project", "install"})
					if err != nil {
						t.Fatal(err)
					}
					target, _ := url.Parse("https://index.example/simple/project/")
					route, err := options.RouteForRequest(proxy.Request{URL: *target})
					if err != nil || route.TLS.RootCAs == nil {
						t.Fatalf("relative trust not loaded: %v", err)
					}
					if !route.TLS.RootCAs.Equal(configPool(t, ca)) {
						t.Fatal("environment CA did not replace default roots")
					}
				})
			}
		}
	}
}

func TestPoetryVerificationOverridesCertificatePath(t *testing.T) {
	root := isolatedPoetryProject(t)
	config := poetryInvocationConfig(t)
	template, err := os.ReadFile("testdata/verification-settings.toml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, verify, bundle, client string
		insecure, fail               bool
	}{
		{name: "true uses environment trust", verify: "true", bundle: config.CACertificatePath},
		{name: "false ignores stale trust", verify: "false", bundle: "/ignored/missing.pem", insecure: true},
		{name: "path overrides old cert", verify: strconv.Quote(config.CACertificatePath), bundle: "/ignored/missing.pem"},
		{name: "client certificate remains independent", verify: "false", client: "/missing/client.pem", insecure: true, fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("REQUESTS_CA_BUNDLE", test.bundle)
			data := fmt.Sprintf(string(template), strconv.Quote("/shadowed/missing.pem"), test.verify, strconv.Quote(test.client))
			path := filepath.Join(root, "poetry.toml")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
			options, err := manager.ProxyOptions([]string{"--directory", root, "install"})
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse("https://index.example/simple/project/")
			route, err := options.RouteForRequest(proxy.Request{URL: *target})
			if test.fail {
				if err == nil || strings.Contains(err.Error(), "client.pem") {
					t.Fatalf("missing/unsafe client certificate error: %v", err)
				}
				return
			}
			if err != nil || route.TLS.InsecureSkipVerify != test.insecure {
				t.Fatalf("effective verification was not honored: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatal("source TLS configuration changed")
			}
		})
	}
}
