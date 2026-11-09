// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// fakeProxyPackageManager is a package manager that supports proxy mode.
type fakeProxyPackageManager struct {
	fakePackageManager
	upstreamErr    error
	prepareCommand func(ctx context.Context, command []string, config proxy.ClientConfig) error

	proxyCommandCalls int
}

func (manager *fakeProxyPackageManager) UpstreamProxy([]string) (httpproxy.Config, error) {
	return httpproxy.Config{}, manager.upstreamErr
}

func (manager *fakeProxyPackageManager) ProxyCommand(ctx context.Context, command []string, config proxy.ClientConfig) (proxy.CommandSpec, error) {
	manager.proxyCommandCalls++
	if manager.prepareCommand != nil {
		if err := manager.prepareCommand(ctx, command, config); err != nil {
			return proxy.CommandSpec{}, err
		}
	}
	return proxy.CommandSpec{Executable: "true"}, nil
}

// fakePackageManager is a package manager that only supports dry-run resolution.
type fakePackageManager struct {
	projectDirectory string
	resolveCalls     int
	runCalls         int
}

func (*fakePackageManager) Executable() string { return "fakepm" }

func (manager *fakePackageManager) ProjectDirectory([]string) (string, error) {
	return manager.projectDirectory, nil
}

func (manager *fakePackageManager) RunCommand(context.Context, []string) error {
	manager.runCalls++
	return nil
}

func (manager *fakePackageManager) ResolveInstallTargets(context.Context, []string) (*pm.Set[pm.Package], error) {
	manager.resolveCalls++
	return pm.NewSet[pm.Package](), nil
}

func TestProxyEnabled(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "true", want: false},
		{value: " 1", want: false},
		{value: "1", want: true},
	}
	for _, tt := range tests {
		t.Setenv(proxyEnabledVar, tt.value)
		if got := proxyEnabled(); got != tt.want {
			t.Errorf("proxyEnabled() with %s=%q = %v, want %v", proxyEnabledVar, tt.value, got, tt.want)
		}
	}
}

func TestRedactCommandArgumentsRemovesURLCredentials(t *testing.T) {
	command := []string{
		"pip", "install",
		"--index-url=https://user:password@index.example/simple?token=secret#fragment",
		"--extra-index-url", "https://cdn.example/simple?api_key=secret",
		"-ihttps://short:password@short.example/simple?token=secret",
		"project @ https://artifact:password@files.example/project-1.0.whl?signature=secret#sha256=digest",
	}
	got := redactCommandArguments(command)
	want := []string{
		"pip", "install",
		"--index-url=https://index.example/simple",
		"--extra-index-url", "https://cdn.example/simple",
		"-ihttps://short.example/simple",
		"project @ https://files.example/project-1.0.whl",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("redactCommandArguments() = %q, want %q", got, want)
	}
	if command[2] == got[2] {
		t.Fatal("redactCommandArguments mutated or reused the original credentialed argument")
	}
}

func TestRedactCommandArgumentsReplacesUnparseableURLs(t *testing.T) {
	for _, test := range []struct {
		name, argument, want string
	}{
		{"invalid path escape", "--index-url=https://user:password@index.example/%zz?token=secret", "--index-url=[REDACTED_URL]"},
		{"invalid credentials", "https://user:pass%zz@index.example/simple", "[REDACTED_URL]"},
		{"invalid port", "https://user:password@index.example:invalid/simple", "[REDACTED_URL]"},
		{"invalid host", "project @ https://user:password@[invalid/path?token=secret", "project @ [REDACTED_URL]"},
		{"missing host", "-ihttps:///private-path?token=secret", "-i[REDACTED_URL]"},
		{"invalid fragment", "HTTPS://user:password@index.example/simple#%zz", "[REDACTED_URL]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := []string{"pip", "install", test.argument, "project"}
			original := slices.Clone(command)
			got := redactCommandArguments(command)
			want := []string{"pip", "install", test.want, "project"}
			if !slices.Equal(got, want) {
				t.Fatalf("redacted command = %q, want %q", got, want)
			}
			if !slices.Equal(command, original) {
				t.Fatal("redaction changed the original package-manager arguments")
			}
		})
	}
}

func TestRunThroughProxyReportsUpstreamResolutionFailure(t *testing.T) {
	manager := &fakeProxyPackageManager{upstreamErr: errors.New("bad proxy configuration")}

	commandErr, err := runThroughProxy(context.Background(), manager, []string{"install"}, nil)
	if err == nil || !strings.Contains(err.Error(), "bad proxy configuration") {
		t.Errorf("runThroughProxy() setup error = %v, want the upstream resolution failure", err)
	}
	if commandErr != nil || manager.proxyCommandCalls != 0 {
		t.Errorf("command error %v, ProxyCommand calls %d; want nil, 0", commandErr, manager.proxyCommandCalls)
	}
}

func TestRunThroughProxyWithoutControllerLeavesPyPIArtifactUnmodified(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "artifact bytes")
	}))
	defer upstream.Close()
	manager := &fakeProxyPackageManager{prepareCommand: func(_ context.Context, _ []string, config proxy.ClientConfig) error {
		proxyURL, _ := url.Parse(config.URL)
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		response, err := client.Get(upstream.URL + "/project-1.0.tar.gz")
		if err != nil {
			return err
		}
		defer response.Body.Close() //nolint:errcheck
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusOK || string(body) != "artifact bytes" {
			return fmt.Errorf("generic proxy response = %d %q", response.StatusCode, body)
		}
		return nil
	}}
	commandErr, setupErr := runThroughProxy(context.Background(), manager, []string{"install", "project"}, nil)
	if setupErr != nil || commandErr != nil || upstreamHits.Load() != 1 {
		t.Fatalf("runThroughProxy() command=%v setup=%v upstream hits=%d; want nil, nil, 1", commandErr, setupErr, upstreamHits.Load())
	}
}

func TestPublicationHTTPClientUsesCapturedUpstream(t *testing.T) {
	upstreamHits := atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamHits.Add(1)
		if request.URL.Host != "registry.invalid" {
			t.Errorf("upstream request host = %q, want registry.invalid", request.URL.Host)
		}
		_, _ = io.WriteString(w, "through upstream")
	}))
	defer upstream.Close()
	client := newPublicationHTTPClient(proxy.Options{Upstream: httpproxy.Config{HTTPProxy: upstream.URL}})
	response, err := client.Get("http://registry.invalid/metadata")
	if err != nil {
		t.Fatalf("proxy-only request failed: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "through upstream" || upstreamHits.Load() != 1 {
		t.Fatalf("body=%q upstream hits=%d; want proxy response and one hit", body, upstreamHits.Load())
	}
}

func TestRunFirewallUsesProxyOnlyWhenEnabledAndSupported(t *testing.T) {
	tests := []struct {
		name          string
		flag          string
		supportsProxy bool
		wantProxy     bool
	}{
		{name: "flag unset", flag: "", supportsProxy: true, wantProxy: false},
		{name: "flag not exactly 1", flag: "true", supportsProxy: true, wantProxy: false},
		{name: "flag enabled", flag: "1", supportsProxy: true, wantProxy: true},
		{name: "flag enabled without proxy support", flag: "1", supportsProxy: false, wantProxy: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(proxyEnabledVar, tt.flag)
			t.Setenv(evaluationModeVar, string(evaluationModeLocal))
			t.Setenv("SCFW_HOME", t.TempDir())
			t.Setenv(onWarningVar, "")

			dryRun := &fakePackageManager{projectDirectory: t.TempDir()}
			proxied := &fakeProxyPackageManager{fakePackageManager: fakePackageManager{projectDirectory: t.TempDir()}}
			var manager pm.PackageManager = dryRun
			if tt.supportsProxy {
				manager = proxied
				dryRun = &proxied.fakePackageManager
			}
			registerFakePackageManager(t, manager)

			cmd := RootCmd()
			defer cmd.RemoveCommand(configureCmd, doctorCmd, runCmd)
			cmd.SetArgs([]string{"run", "--", "fakepm", "install"})
			if err := cmd.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("scfw run returned unexpected error: %v", err)
			}

			if tt.wantProxy {
				if proxied.proxyCommandCalls != 1 || dryRun.resolveCalls != 0 || dryRun.runCalls != 0 {
					t.Errorf("proxy runs %d, resolutions %d, direct runs %d; want 1, 0, 0",
						proxied.proxyCommandCalls, dryRun.resolveCalls, dryRun.runCalls)
				}
			} else if proxied.proxyCommandCalls != 0 || dryRun.resolveCalls != 1 || dryRun.runCalls != 1 {
				t.Errorf("proxy runs %d, resolutions %d, direct runs %d; want 0, 1, 1",
					proxied.proxyCommandCalls, dryRun.resolveCalls, dryRun.runCalls)
			}
		})
	}
}

// registerFakePackageManager makes `scfw run -- fakepm ...` use manager.
func registerFakePackageManager(t *testing.T, manager pm.PackageManager) {
	t.Helper()
	previous := packageManagerFactories
	packageManagerFactories = append([]PackageManagerFactory{{
		Names: []string{"fakepm"},
		New: func(context.Context, string, string) (pm.PackageManager, error) {
			return manager, nil
		},
	}}, previous...)
	t.Cleanup(func() { packageManagerFactories = previous })
}

func TestRunThroughProxyReportsHookConfigurationFailure(t *testing.T) {
	manager := &fakeProxyPackageManager{}
	failure := errors.New("invalid hook settings")
	commandErr, setupErr := runThroughProxy(context.Background(), manager, []string{"install"}, func(context.Context, *http.Client) ([]proxy.RequestHook, error) {
		return nil, failure
	})
	if commandErr != nil || !errors.Is(setupErr, failure) || manager.proxyCommandCalls != 0 {
		t.Fatalf("command=%v setup=%v preparations=%d; want nil, configuration failure, 0", commandErr, setupErr, manager.proxyCommandCalls)
	}
}

func TestRunFirewallConstructsAllRegisteredHooksForEachInvocation(t *testing.T) {
	t.Setenv(proxyEnabledVar, "1")
	t.Setenv(evaluationModeVar, string(evaluationModeDatadog))
	t.Setenv(onWarningVar, "")
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamHits++ }))
	defer upstream.Close()
	manager := &fakeProxyPackageManager{fakePackageManager: fakePackageManager{projectDirectory: t.TempDir()}}
	registerFakePackageManager(t, manager)
	var factories, observed []int
	var clients []*http.Client
	var invocationContext context.Context
	makeFactory := func(index int) proxyHookFactory {
		return func(ctx context.Context, gotManager pm.PackageManager, command []string, client *http.Client, evaluate func(context.Context, pm.Package, error) error) (proxy.RequestHook, error) {
			if gotManager != manager || !slices.Equal(command, []string{"install", "project"}) || evaluate == nil {
				t.Fatal("hook factory did not receive invocation inputs")
			}
			if index == 1 {
				invocationContext = ctx
				clients = append(clients, client)
			} else if ctx != invocationContext || client != clients[len(clients)-1] {
				t.Fatal("hooks did not share invocation context and registry client")
			}
			factories = append(factories, index)
			return func(context.Context, proxy.Request) (proxy.ResponseHook, error) {
				observed = append(observed, index)
				if index == 2 {
					return nil, errors.New("blocked by second hook")
				}
				return nil, nil
			}, nil
		}
	}
	packageManagerFactories[0].ProxyHooks = []proxyHookFactory{makeFactory(1), makeFactory(2)}
	manager.prepareCommand = func(_ context.Context, _ []string, config proxy.ClientConfig) error {
		proxyURL, _ := url.Parse(config.URL)
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport}).Get(upstream.URL + "/artifact")
		if err != nil {
			return err
		}
		defer response.Body.Close() //nolint:errcheck
		if response.StatusCode != http.StatusForbidden {
			return fmt.Errorf("response=%d, want rejection by registered hook", response.StatusCode)
		}
		return nil
	}
	for range 2 {
		func() {
			cmd := RootCmd()
			defer cmd.RemoveCommand(configureCmd, doctorCmd, runCmd)
			cmd.SetArgs([]string{"run", "--", "fakepm", "install", "project"})
			if err := cmd.ExecuteContext(context.Background()); err != nil {
				t.Fatal(err)
			}
		}()
		if invocationContext.Err() == nil {
			t.Fatal("invocation context remained live after the command finished")
		}
	}
	if !slices.Equal(factories, []int{1, 2, 1, 2}) || !slices.Equal(observed, factories) || upstreamHits != 0 || clients[0] == clients[1] {
		t.Fatalf("factories=%v requests=%v upstream=%d; expected fresh, ordered hooks for each run", factories, observed, upstreamHits)
	}
}
