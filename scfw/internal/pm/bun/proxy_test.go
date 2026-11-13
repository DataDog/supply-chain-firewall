// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

var version14 = pm.Version{Major: 1, Minor: 4, Patch: 4}

func TestProxyOptionsRouting(t *testing.T) {
	isolateBun(t)
	t.Chdir(t.TempDir())
	t.Setenv("HTTPS_PROXY", "http://secure.example:1")
	t.Setenv("HTTP_PROXY", "http://plain.example:2")
	t.Setenv("NO_PROXY", "internal.example")
	options, err := (Bun{installed: version14}).ProxyOptions([]string{"install"})
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"https://registry.example/": "http://secure.example:1", "http://registry.example/": "http://plain.example:2", "https://a.internal.example/": "",
	} {
		parsed, _ := url.Parse(target)
		got, err := options.ProxyForURL(parsed)
		if err != nil || (got == nil) != (want == "") || (got != nil && got.String() != want) {
			t.Errorf("%s -> %v, %v; want %q", target, got, err, want)
		}
	}
	t.Setenv("NO_PROXY", "*")
	options, _ = (Bun{installed: version14}).ProxyOptions([]string{"install"})
	if got, _ := options.ProxyForURL(&url.URL{Scheme: "https", Host: "any.example"}); got != nil {
		t.Fatalf("NO_PROXY=* routed through %v", got)
	}
}

func TestProxyOptionsPrefersLowercaseVariables(t *testing.T) {
	isolateBun(t)
	t.Chdir(t.TempDir())
	t.Setenv("HTTPS_PROXY", "http://upper.example:1")
	t.Setenv("https_proxy", "http://lower.example:1")
	t.Setenv("HTTP_PROXY", "http://upper.example:2")
	t.Setenv("http_proxy", "http://lower.example:2")
	t.Setenv("NO_PROXY", "lower-bypassed.example")
	t.Setenv("no_proxy", "upper-bypassed.example")
	options, err := (Bun{installed: version14}).ProxyOptions([]string{"install"})
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"https://registry.example/": "http://lower.example:1", "http://registry.example/": "http://lower.example:2",
		"https://upper-bypassed.example/": "", "https://lower-bypassed.example/": "http://lower.example:1",
	} {
		parsed, _ := url.Parse(target)
		got, _ := options.ProxyForURL(parsed)
		if (got == nil) != (want == "") || (got != nil && got.String() != want) {
			t.Errorf("%s -> %v, want %q", target, got, want)
		}
	}
}

// Bun 1.4 bypasses a port-qualified NO_PROXY entry for that port only; Bun 1.2
// and 1.3 never match it.
func TestProxyOptionsPortQualifiedNoProxy(t *testing.T) {
	isolateBun(t)
	t.Chdir(t.TempDir())
	t.Setenv("https_proxy", "http://proxy.example:1")
	t.Setenv("no_proxy", "127.0.0.1:8443,registry.example:443")
	for _, test := range []struct {
		minor  int
		target string
		direct bool
	}{
		{4, "https://127.0.0.1:8443/", true},
		{4, "https://127.0.0.1:9443/", false},
		{4, "https://registry.example/", true},
		{3, "https://127.0.0.1:8443/", false},
		{2, "https://registry.example/", false},
	} {
		options, err := (Bun{installed: pm.Version{Major: 1, Minor: test.minor}}).ProxyOptions([]string{"install"})
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := url.Parse(test.target)
		if got, _ := options.ProxyForURL(parsed); (got == nil) != test.direct {
			t.Errorf("1.%d %s -> %v, want direct=%v", test.minor, test.target, got, test.direct)
		}
	}
}

func TestProxyOptionsDirectAndInvalid(t *testing.T) {
	isolateBun(t)
	t.Chdir(t.TempDir())
	options, err := (Bun{installed: version14}).ProxyOptions([]string{"install"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := options.ProxyForURL(&url.URL{Scheme: "https", Host: "registry.example"}); got != nil {
		t.Fatalf("unset proxy routed through %v", got)
	}
	t.Setenv("HTTPS_PROXY", "socks5://user:secret@proxy.example")
	if _, err := (Bun{installed: version14}).ProxyOptions([]string{"install"}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error = %v, want a rejection without the credential", err)
	}
}

func TestProxyCommand(t *testing.T) {
	isolateBun(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("No_Proxy", "localhost")
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: ca}
	manager := Bun{executable: "/bin/bun", installed: version14}
	spec, err := manager.ProxyCommand(context.Background(), []string{"--silent", "add", "--cafile", "mine.pem", "x"}, config)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"--silent", "add", "--cafile=" + ca, "x"}; !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
	for key, want := range map[string]string{
		"HTTPS_PROXY": config.URL, "NO_PROXY": noProxySentinel, "No_Proxy": noProxySentinel,
		"NODE_EXTRA_CA_CERTS": ca, "GIT_SSL_CAINFO": ca,
	} {
		if spec.EnvOverrides[key] != want {
			t.Errorf("%s = %q, want %q", key, spec.EnvOverrides[key], want)
		}
	}
	run, err := manager.ProxyCommand(context.Background(), []string{"run", "build", "--cafile", "y"}, config)
	if err != nil || !slices.Equal(run.Args, []string{"run", "build", "--cafile", "y"}) {
		t.Fatalf("run args = %q, %v", run.Args, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("ProxyCommand wrote files in the project")
	}
	if _, err := (Bun{installed: pm.Version{Major: 1, Minor: 1}}).ProxyCommand(context.Background(), nil, config); err == nil {
		t.Fatal("want bun 1.1 rejected")
	}
}
