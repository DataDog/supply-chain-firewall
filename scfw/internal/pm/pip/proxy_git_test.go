// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func isolatePipGit(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_HTTP_USER_AGENT"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

// Run the native Git child with the exact environment prepared for pip, without
// needing a package build to decide which upstream received its request.
type pipGitChild struct {
	Pip
	executable string
	args       []string
	config     proxy.ClientConfig
}

func (child *pipGitChild) ProxyCommand(ctx context.Context, args []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	child.config = config
	spec, err := child.Pip.ProxyCommand(ctx, args, config)
	spec.Executable, spec.Args = child.executable, child.args
	return spec, err
}

func TestPipNativeGitKeepsEnvironmentProxy(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git required for native child routing")
	}
	for _, version := range []pm.Version{{Major: 22, Minor: 2}, {Major: 24}, {Major: 24, Minor: 1}, {Major: 26, Minor: 1}, {Major: 26, Minor: 2}} {
		for _, agent := range []string{"git/2.55.0", "custom-git-agent"} {
			t.Run(version.String()+"/"+agent, func(t *testing.T) {
				manager := goDiscoveryPip(t)
				manager.version = version
				isolatePipGit(t)
				t.Setenv("GIT_HTTP_USER_AGENT", agent)
				var nativeCalls, pipCalls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					nativeCalls.Add(1)
					http.Error(w, "native route", http.StatusBadGateway)
				}))
				defer upstream.Close()
				registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					pipCalls.Add(1)
					http.Error(w, "pip route", http.StatusBadGateway)
				}))
				defer registry.Close()
				t.Setenv("HTTPS_PROXY", upstream.URL)
				t.Setenv("PIP_PROXY", registry.URL)
				target := "https://git.example.invalid/repo.git"
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				args := []string{"ls-remote", target}
				if err := exec.CommandContext(ctx, git, args...).Run(); err == nil {
					t.Fatal("fixture must fail after recording the route")
				}
				if nativeCalls.Load() == 0 || pipCalls.Load() != 0 {
					t.Fatal("native control did not use HTTPS_PROXY")
				}
				nativeCalls.Store(0)
				command := []string{"install", "git+" + target}
				options, err := manager.ProxyOptions(command)
				if err != nil {
					t.Fatal(err)
				}
				child := &pipGitChild{Pip: manager, executable: git, args: args}
				commandErr, setupErr := proxy.Run(ctx, options, command, child)
				if setupErr != nil || commandErr == nil {
					t.Fatalf("command=%v setup=%v", commandErr, setupErr)
				}
				if nativeCalls.Load() == 0 || pipCalls.Load() != 0 {
					t.Fatalf("protected Git used pip route: native=%d pip=%d", nativeCalls.Load(), pipCalls.Load())
				}
				for _, config := range child.config.AdditionalClients {
					if _, err := os.Stat(filepath.Dir(config.CACertificatePath)); !os.IsNotExist(err) {
						t.Fatalf("Git client temporary material remains: %v", err)
					}
				}
			})
		}
	}
}

func TestPipRegistryAndGitTrustStaySeparate(t *testing.T) {
	manager := goDiscoveryPip(t)
	isolatePipGit(t)
	roots := make([]*x509.Certificate, 0, 2)
	paths := make([]string, 0, 2)
	for range 2 {
		server, err := proxy.Start(context.Background(), proxy.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		path := server.ClientConfig().CACertificatePath
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal("invalid fixture CA")
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		roots, paths = append(roots, root), append(paths, path)
	}
	t.Setenv("PIP_CERT", paths[0])
	t.Setenv("GIT_SSL_CAINFO", paths[1])
	options, err := manager.ProxyOptions([]string{"install", "project"})
	if err != nil {
		t.Fatal(err)
	}
	git := options.AdditionalClients["git"]
	if git.RouteForRequest == nil {
		t.Fatal("native Git has no independent route")
	}
	target, _ := url.Parse("https://git.example.invalid/repo.git/info/refs")
	route, err := git.RouteForRequest(proxy.Request{URL: *target})
	if err != nil {
		t.Fatal(err)
	}
	for index, pool := range []*x509.CertPool{options.UpstreamTLS.RootCAs, route.TLS.RootCAs} {
		for candidate, root := range roots {
			_, err := root.Verify(x509.VerifyOptions{Roots: pool})
			if (err == nil) != (index == candidate) {
				t.Fatalf("client%d trusts CA%d: %v", index, candidate, err)
			}
		}
	}
}
