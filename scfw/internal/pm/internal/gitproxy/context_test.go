// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"context"
	"encoding/pem"
	"net"
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

func countingGitProxy(t *testing.T, count *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); http.NotFound(w, r) }))
	t.Cleanup(server.Close)
	return server
}

func runGitProcess(directory string, overrides map[string]string, args ...string) error {
	command := exec.Command("git", args...)
	command.Dir = directory
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range overrides {
		command.Env = append(command.Env, key+"="+value)
	}
	return command.Run()
}

func gitThroughSCFW(t *testing.T, directory string, settings *Settings, args ...string) {
	t.Helper()
	server, err := proxy.Start(context.Background(), proxy.Options{RouteForRequest: settings.Route})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	config := server.ClientConfig()
	config.AdditionalClients = map[string]proxy.ClientConfig{}
	for name, options := range settings.AdditionalClients() {
		client, err := proxy.Start(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		config.AdditionalClients[name] = client.ClientConfig()
	}
	overrides := config.EnvironmentOverrides()
	if err := settings.ChildOverrides(overrides, config); err != nil {
		t.Fatal(err)
	}
	_ = runGitProcess(directory, overrides, args...)
}

func TestCloneIgnoresCallerOriginProxy(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var callerHits, dependencyHits atomic.Int32
	caller := countingGitProxy(t, &callerHits)
	dependency := countingGitProxy(t, &dependencyHits)
	if err := runGitProcess(directory, nil, "init"); err != nil {
		t.Fatal(err)
	}
	if err := runGitProcess(directory, nil, "config", "remote.origin.proxy", caller.URL); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
	t.Setenv("GIT_CONFIG_VALUE_0", dependency.URL)
	_ = runGitProcess(directory, nil, "clone", "http://registry.example/dependency", filepath.Join(directory, "native"))
	if dependencyHits.Load() == 0 || callerHits.Load() != 0 {
		t.Fatalf("unexpected native Git routing: caller=%d dependency=%d", callerHits.Load(), dependencyHits.Load())
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	before := dependencyHits.Load()
	gitThroughSCFW(t, directory, settings, "clone", "http://registry.example/dependency", filepath.Join(directory, "proxied"))
	if callerHits.Load() != 0 || dependencyHits.Load() == before {
		t.Fatalf("native clone ignored caller remote.origin.proxy, but SCFW used it: caller=%d dependency=%d", callerHits.Load(), dependencyHits.Load())
	}
}

func TestUsernameScopedGitProxy(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var genericHits, scopedHits atomic.Int32
	generic := countingGitProxy(t, &genericHits)
	scoped := countingGitProxy(t, &scopedHits)
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
	t.Setenv("GIT_CONFIG_VALUE_0", generic.URL)
	t.Setenv("GIT_CONFIG_KEY_1", "http.http://alice@registry.example/.proxy")
	t.Setenv("GIT_CONFIG_VALUE_1", scoped.URL)
	target := "http://alice@registry.example/repository"
	_ = runGitProcess(directory, nil, "ls-remote", target)
	if scopedHits.Load() == 0 || genericHits.Load() != 0 {
		t.Fatalf("unexpected native Git routing: generic=%d scoped=%d", genericHits.Load(), scopedHits.Load())
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	before := scopedHits.Load()
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if genericHits.Load() != 0 || scopedHits.Load() == before {
		t.Fatalf("username-scoped proxy lost through SCFW: generic=%d scoped=%d", genericHits.Load(), scopedHits.Load())
	}
}

func TestGitNoProxyUsesCurlMatching(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var originHits, proxyHits atomic.Int32
	origin := countingGitProxy(t, &originHits)
	upstream := countingGitProxy(t, &proxyHits)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
	t.Setenv("GIT_CONFIG_VALUE_0", upstream.URL)
	t.Setenv("NO_PROXY", strings.TrimPrefix(origin.URL, "http://"))
	target := origin.URL + "/repository"
	_ = runGitProcess(directory, nil, "ls-remote", target)
	if proxyHits.Load() == 0 || originHits.Load() != 0 {
		t.Fatalf("unexpected native Git routing: origin=%d proxy=%d", originHits.Load(), proxyHits.Load())
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	before := proxyHits.Load()
	gitThroughSCFW(t, directory, settings, "ls-remote", target)
	if originHits.Load() != 0 || proxyHits.Load() == before {
		t.Fatalf("SCFW bypassed a proxy that native Git used: origin=%d proxy=%d", originHits.Load(), proxyHits.Load())
	}
}

func TestCloneIgnoresCallerConditionalIncludes(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	if err := runGitProcess(directory, nil, "init"); err != nil {
		t.Fatal(err)
	}
	included := filepath.Join(directory, "included.conf")
	if err := runGitProcess(directory, nil, "config", "--file", included, "http.proxy", "http://caller.example:8080"); err != nil {
		t.Fatal(err)
	}
	global := filepath.Join(directory, "global.conf")
	if err := runGitProcess(directory, nil, "config", "--file", global, "http.proxy", "http://dependency.example:8080"); err != nil {
		t.Fatal(err)
	}
	if err := runGitProcess(directory, nil, "config", "--file", global, "includeIf.gitdir:"+filepath.Join(directory, ".git")+".path", included); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_DIR", filepath.Join(directory, ".git"))
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("http://registry.example/repo")
	values, err := settings.Values(target)
	if err != nil || values["proxy"] != "http://dependency.example:8080" {
		t.Fatalf("caller conditional include leaked into dependency: %v / %v", values, err)
	}
}

func TestGitIdentityProfilesSeparateRoutingAndTLS(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	keys := []string{"http.https://alice@registry.example/.proxy", "http.https://alice@registry.example/.sslVerify", "http.https://bob@registry.example/.proxy", "http.https://bob@registry.example/.sslVerify"}
	values := []string{"http://alice-proxy.example:8080", "false", "http://bob-proxy.example:8080", "true"}
	t.Setenv("GIT_CONFIG_COUNT", strconv.Itoa(len(keys)))
	for i, key := range keys {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(i), key)
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(i), values[i])
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	clients := settings.AdditionalClients()
	if len(clients) != 2 {
		t.Fatalf("identity listeners: %d", len(clients))
	}
	target, _ := url.Parse("https://registry.example/repository/info/refs")
	for _, profile := range settings.profiles {
		options := clients[profile.name]
		first, err := options.RouteForRequest(proxy.Request{URL: *target})
		if err != nil {
			t.Fatal(err)
		}
		again, err := options.RouteForRequest(proxy.Request{URL: *target})
		if err != nil || again != first {
			t.Fatal("identity route was not cached")
		}
		if first.ProxyURL.Hostname() != profile.scope.User.Username()+"-proxy.example" || first.TLS.InsecureSkipVerify != (profile.scope.User.Username() == "alice") {
			t.Fatal("identity routing or TLS crossed users")
		}
	}
}

func TestGitNoProxyMatchesNativeGit(t *testing.T) {
	for _, pattern := range []string{"", "*", "127.0.0.1", "127.0.0.1:PORT", "127.0.0.0/8", "127.0.0.0/32", "localhost", ".localhost", "LOCALHOST.", "otherhost", "host, localhost", "*.localhost"} {
		t.Run(pattern, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			var originHits, proxyHits atomic.Int32
			origin := countingGitProxy(t, &originHits)
			upstream := countingGitProxy(t, &proxyHits)
			target := origin.URL + "/repo"
			if strings.Contains(strings.ToLower(pattern), "localhost") || pattern == "otherhost" || strings.Contains(pattern, "host,") {
				target = strings.Replace(target, "127.0.0.1", "localhost", 1)
			}
			parsed, _ := url.Parse(target)
			pattern = strings.ReplaceAll(pattern, "PORT", parsed.Port())
			t.Setenv("NO_PROXY", pattern)
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
			t.Setenv("GIT_CONFIG_VALUE_0", upstream.URL)
			_ = runGitProcess(directory, nil, "ls-remote", target)
			nativeDirect := originHits.Load() > 0
			if !nativeDirect && proxyHits.Load() == 0 {
				t.Fatal("native Git reached neither origin nor upstream")
			}
			originHits.Store(0)
			proxyHits.Store(0)
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			gitThroughSCFW(t, directory, settings, "ls-remote", target)
			if (originHits.Load() > 0) != nativeDirect || (proxyHits.Load() > 0) == nativeDirect {
				t.Fatalf("native direct=%v, SCFW origin=%d proxy=%d", nativeDirect, originHits.Load(), proxyHits.Load())
			}
		})
	}
}

func TestGitNoProxyHostBoundaries(t *testing.T) {
	for _, test := range []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", "example.com", true}, {"sub.example.com", ".example.com", true}, {"notexample.com", "example.com", false},
		{"example.com:443", "example.com:443", false}, {"example.com.", "EXAMPLE.COM.", true}, {"[::1]:443", "::1", true},
		{"[::1]:443", "[::1]", false}, {"127.0.0.1:443", "127.0.0.0/8", true}, {"127.0.0.1", "0.0.0.0/0", false},
	} {
		target, _ := url.Parse("https://" + test.host + "/")
		if got := bypassesProxy(target, test.pattern); got != test.want {
			t.Errorf("%s / %s: %v", test.host, test.pattern, got)
		}
	}
}

func TestGitUsernameListenersInterceptHTTPS(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); http.NotFound(w, r) }))
	defer origin.Close()
	ca := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_COUNT", "3")
	for index, key := range []string{"http." + strings.Replace(origin.URL, "https://", "https://alice@", 1) + "/.sslCAInfo", "http." + strings.Replace(origin.URL, "https://", "https://bob@", 1) + "/.sslCAInfo", "http.sslVerify"} {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), key)
		value := ca
		if index == 2 {
			value = "true"
		}
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), value)
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"alice", "bob"} {
		target := strings.Replace(origin.URL, "https://", "https://"+username+"@", 1) + "/repository"
		before := hits.Load()
		_ = runGitProcess(directory, nil, "ls-remote", target)
		if hits.Load() == before {
			t.Fatal("native Git did not trust scoped CA")
		}
		before = hits.Load()
		gitThroughSCFW(t, directory, settings, "ls-remote", target)
		if hits.Load() == before {
			t.Fatal("username listener lost interception or outbound TLS trust")
		}
	}
}

func TestGitSnapshotRetainsRelativeConfigurationPaths(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	global := filepath.Join(directory, "global.conf")
	include := filepath.Join(directory, "include.conf")
	for _, args := range [][]string{{"config", "--file", global, "include.path", "include.conf"}, {"config", "--file", include, "http.proxy", "http://relative.example:8080"}} {
		if err := runGitProcess(directory, nil, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "global.conf")
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("http://registry.example/repo")
	values, err := settings.Values(target)
	if err != nil || values["proxy"] != "http://relative.example:8080" {
		t.Fatalf("relative configuration lost: %v / %v", values, err)
	}
}

func TestGitNoProxyIPv6LiteralMatchesNativeGit(t *testing.T) {
	for _, pattern := range []string{"::1", "[::1]", "::1:PORT", "*", ""} {
		t.Run(pattern, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			listener, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Skip("IPv6 loopback unavailable")
			}
			var originHits, proxyHits atomic.Int32
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originHits.Add(1); http.NotFound(w, r) }))
			_ = origin.Listener.Close()
			origin.Listener = listener
			origin.Start()
			defer origin.Close()
			upstream := countingGitProxy(t, &proxyHits)
			target := origin.URL + "/repo"
			parsed, _ := url.Parse(target)
			t.Setenv("NO_PROXY", strings.ReplaceAll(pattern, "PORT", parsed.Port()))
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
			t.Setenv("GIT_CONFIG_VALUE_0", upstream.URL)
			_ = runGitProcess(directory, nil, "ls-remote", target)
			direct := originHits.Load() > 0
			if !direct && proxyHits.Load() == 0 {
				t.Fatal("native Git reached neither destination")
			}
			originHits.Store(0)
			proxyHits.Store(0)
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			gitThroughSCFW(t, directory, settings, "ls-remote", target)
			if (originHits.Load() > 0) != direct || (proxyHits.Load() > 0) == direct {
				t.Fatalf("native direct=%v, SCFW origin=%d proxy=%d", direct, originHits.Load(), proxyHits.Load())
			}
		})
	}
}

func TestGitIdentityListenersRetainNativePathPrecedence(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var genericHits, aliceHits, bobHits atomic.Int32
	generic := countingGitProxy(t, &genericHits)
	alice := countingGitProxy(t, &aliceHits)
	bob := countingGitProxy(t, &bobHits)
	keys := []string{"http.http://alice@registry.example/.proxy", "http.http://bob@registry.example/.proxy", "http.http://registry.example/deeper/.proxy"}
	values := []string{alice.URL, bob.URL, generic.URL}
	t.Setenv("GIT_CONFIG_COUNT", strconv.Itoa(len(keys)))
	for index, key := range keys {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), key)
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), values[index])
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		target   string
		selected *atomic.Int32
	}{
		{"http://alice@registry.example/repository", &aliceHits},
		{"http://bob@registry.example/repository", &bobHits},
		{"http://alice@registry.example/deeper/repository", &genericHits},
	} {
		aliceHits.Store(0)
		bobHits.Store(0)
		genericHits.Store(0)
		_ = runGitProcess(directory, nil, "ls-remote", test.target)
		native := test.selected.Load()
		if native == 0 || aliceHits.Load()+bobHits.Load()+genericHits.Load() != native {
			t.Fatal("native Git did not select expected scope")
		}
		gitThroughSCFW(t, directory, settings, "ls-remote", test.target)
		if test.selected.Load() <= native || aliceHits.Load()+bobHits.Load()+genericHits.Load() != test.selected.Load() {
			t.Fatal("interception lost Git's username/path precedence")
		}
	}
}
