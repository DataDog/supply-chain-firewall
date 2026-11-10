// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGitDoesNotUseRegistrySSLFile(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	origin := gitTLSOrigin(t, &hits)
	ca := filepath.Join(directory, "registry.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	target := origin.URL + "/repo"
	_ = runGitProcess(directory, nil, "ls-remote", target)

	if hits.Load() != 0 {
		t.Skip("this Git build consumes SSL_CERT_FILE")
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if hits.Load() != 0 {
		t.Fatalf("SCFW trusted a registry CA that native Git rejected: origin requests=%d", hits.Load())
	}
}

func TestGitMatchesOriginalRemotePath(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	origin := gitTLSOrigin(t, &hits)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http."+origin.URL+"/repo/info/.sslVerify")
	t.Setenv("GIT_CONFIG_VALUE_0", "false")
	target := origin.URL + "/repo"
	_ = runGitProcess(directory, nil, "ls-remote", target)
	if hits.Load() != 0 {
		t.Fatal("native Git unexpectedly disabled remote verification")
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if hits.Load() != 0 {
		t.Fatalf("SCFW matched generated info/refs path and disabled verification: origin requests=%d", hits.Load())
	}
}

func TestGitDoesNotLoadDisabledCA(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	origin := gitTLSOrigin(t, &hits)
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "http.sslVerify")
	t.Setenv("GIT_CONFIG_VALUE_0", "false")
	t.Setenv("GIT_CONFIG_KEY_1", "http.sslCAInfo")
	t.Setenv("GIT_CONFIG_VALUE_1", filepath.Join(directory, "missing.pem"))
	target := origin.URL + "/repo"
	_ = runGitProcess(directory, nil, "ls-remote", target)
	if hits.Load() == 0 {
		t.Skip("native Git requires the CA even with verification disabled")
	}
	before := hits.Load()
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if hits.Load() == before {
		t.Fatal("SCFW blocked the request on CA material ignored by native Git with verification disabled")
	}
}

func TestGitPinnedPublicKeyStillWorks(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	origin := gitTLSOrigin(t, &hits)
	ca := filepath.Join(directory, "git.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(origin.Certificate().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(publicKey)
	t.Setenv("GIT_SSL_CAINFO", ca)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http.pinnedPubkey")
	t.Setenv("GIT_CONFIG_VALUE_0", "sha256//"+base64.StdEncoding.EncodeToString(digest[:]))
	target := origin.URL + "/repo"
	_ = runGitProcess(directory, nil, "ls-remote", target)
	if hits.Load() == 0 {
		t.Skip("native Git did not accept correct public-key pin")
	}
	before := hits.Load()
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if hits.Load() == before {
		t.Fatal("native Git accepted original pin, but interception failed before reaching origin")
	}
}

func TestGitPinFormatsMatchNative(t *testing.T) {
	for _, format := range []string{"PEM", "DER", "multiple hashes", "scoped pin", "pin without verification"} {
		t.Run(format, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			var hits atomic.Int32
			origin := gitTLSOrigin(t, &hits)
			publicKey, err := x509.MarshalPKIXPublicKey(origin.Certificate().PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(publicKey)
			pin := "sha256//" + base64.StdEncoding.EncodeToString(digest[:])
			switch format {
			case "PEM", "DER":
				contents := publicKey
				if format == "PEM" {
					contents = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})
				}
				pin = filepath.Join(directory, "pin.pub")
				if err := os.WriteFile(pin, contents, 0600); err != nil {
					t.Fatal(err)
				}
			case "multiple hashes":
				pin = "sha256//" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + ";" + pin
			}
			ca := filepath.Join(directory, "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GIT_SSL_CAINFO", ca)
			t.Setenv("GIT_CONFIG_COUNT", "1")
			key := "http.pinnedPubkey"
			if format == "scoped pin" {
				key = "http." + origin.URL + "/repo.pinnedPubkey"
			}
			t.Setenv("GIT_CONFIG_KEY_0", key)
			t.Setenv("GIT_CONFIG_VALUE_0", pin)
			if format == "pin without verification" {
				t.Setenv("GIT_SSL_NO_VERIFY", "1")
			}
			target := origin.URL + "/repo"
			_ = runGitProcess(directory, nil, "ls-remote", target)
			if hits.Load() == 0 {
				t.Skip("native Git does not support this pin format")
			}
			before := hits.Load()
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			// Proxy runners remove this child-only override; the snapshot keeps the
			// original value for outbound verification.
			if err := os.Unsetenv("GIT_SSL_NO_VERIFY"); err != nil {
				t.Fatal(err)
			}
			gitThroughSCFW(t, directory, settings, "ls-remote", target)
			if hits.Load() == before {
				t.Fatal("correct origin pin failed through interception")
			}
		})
	}
}

func TestGitOverlappingScopesMatchNative(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var proxyHits atomic.Int32
	upstream := countingGitProxy(t, &proxyHits)
	keys := []string{"http.http://*.example.com/team/.proxy", "http.http://alice@foo.*.com/team/repository.sslVerify"}
	values := []string{upstream.URL, "false"}
	t.Setenv("GIT_CONFIG_COUNT", "2")
	for index, key := range keys {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), key)
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), values[index])
	}
	target := "http://alice@foo.example.com/team/repository"
	_ = runGitProcess(directory, nil, "ls-remote", target)
	before := proxyHits.Load()
	if before == 0 {
		t.Fatal("native Git did not use wildcard proxy scope")
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if proxyHits.Load() == before {
		t.Fatal("intersecting host, path, and username scopes lost the original proxy")
	}
	found := false
	for _, profile := range settings.profiles {
		if profile.scope.Hostname() == "foo.example.com" && profile.scope.User != nil && profile.scope.User.Username() == "alice" {
			found = true
			values, err := settings.Values(&profile.target)
			if err != nil || values["proxy"] != upstream.URL || values["sslverify"] != "false" {
				t.Fatalf("lost per-key overlap: %v / %v", values, err)
			}
		}
	}
	if !found {
		t.Fatal("overlapping scope profile is missing")
	}
}

func TestGitRedirectRetainsOriginalTLSSettings(t *testing.T) {
	for _, verify := range []bool{true, false} {
		t.Run(strconv.FormatBool(verify), func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			var destinationHits atomic.Int32
			destination := gitTLSOrigin(t, &destinationHits)
			original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL+r.URL.RequestURI(), http.StatusMovedPermanently)
			}))
			defer original.Close()
			t.Setenv("GIT_CONFIG_COUNT", "2")
			t.Setenv("GIT_CONFIG_KEY_0", "http."+original.URL+"/.sslVerify")
			t.Setenv("GIT_CONFIG_VALUE_0", strconv.FormatBool(verify))
			t.Setenv("GIT_CONFIG_KEY_1", "http."+destination.URL+"/.sslVerify")
			t.Setenv("GIT_CONFIG_VALUE_1", strconv.FormatBool(!verify))
			target := original.URL + "/repo"
			_ = runGitProcess(directory, nil, "ls-remote", target)
			before := destinationHits.Load()
			if (before > 0) == verify {
				t.Fatal("native Git did not retain original verification setting")
			}
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			gitThroughSCFW(t, directory, settings, "ls-remote", target)
			if (destinationHits.Load() > before) == verify {
				t.Fatal("redirect reselected TLS settings against the destination URL")
			}
		})
	}
}

func TestGitNormalizedScopesKeepPerKeySettings(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "http.http://alice@*.example.com:080/team/%72epos/../.sslVerify")
	t.Setenv("GIT_CONFIG_VALUE_0", "false")
	t.Setenv("GIT_CONFIG_KEY_1", "http.http://foo.*.com/team/repository.proxy")
	t.Setenv("GIT_CONFIG_VALUE_1", "http://upstream.example:8080")
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := url.Parse("http://alice@foo.example.com/team/repository")
	expected, err := settings.Values(original)
	if err != nil || expected["sslverify"] != "false" {
		t.Fatalf("native normalized configuration: %v / %v", expected, err)
	}
	server, err := proxy.Start(context.Background(), proxy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	config := server.ClientConfig()
	config.AdditionalClients = map[string]proxy.ClientConfig{}
	clients := settings.AdditionalClients()
	index := 0
	for name := range clients {
		config.AdditionalClients[name] = proxy.ClientConfig{URL: "http://127.0.0.1:" + strconv.Itoa(8000+index), CACertificatePath: config.CACertificatePath}
		index++
	}
	overrides := map[string]string{}
	if err := settings.ChildOverrides(overrides, config); err != nil {
		t.Fatal(err)
	}
	var environment []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			environment = append(environment, entry)
		}
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	data, err := runGitConfiguration(settings.executable, directory, environment, "", "config", "--get-urlmatch", "http.proxy", original.String())
	if err != nil {
		t.Fatal(err)
	}
	selected := strings.TrimSpace(string(data))
	generated, _ := url.Parse("https://generated.example/info/refs")
	for name, client := range config.AdditionalClients {
		if client.URL != selected {
			continue
		}
		route, err := clients[name].RouteForRequest(proxy.Request{URL: *generated})
		if err != nil {
			t.Fatal(err)
		}
		if !route.TLS.InsecureSkipVerify || route.ProxyURL == nil || route.ProxyURL.String() != expected["proxy"] {
			t.Fatal("Git-selected profile lost normalized per-key scope intersection")
		}
		return
	}
	t.Fatal("Git did not select an invocation configuration listener")
}
