// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// fakeProxyPackageManager is a package manager that supports proxy mode.
type fakeProxyPackageManager struct {
	fakePackageManager
	upstreamErr error
	runProxied  func(ctx context.Context, command []string, config proxy.ClientConfig) error

	proxyRunCalls int
}

func (manager *fakeProxyPackageManager) UpstreamProxy([]string) (httpproxy.Config, error) {
	return httpproxy.Config{}, manager.upstreamErr
}

func (manager *fakeProxyPackageManager) RunCommandThroughProxy(ctx context.Context, command []string, config proxy.ClientConfig) error {
	manager.proxyRunCalls++
	if manager.runProxied == nil {
		return nil
	}
	return manager.runProxied(ctx, command, config)
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

func TestRunThroughProxyStopsProxyOnEveryExitPath(t *testing.T) {
	commandFailure := errors.New("install failed")
	tests := []struct {
		name string
		// run stands in for the package manager command; cancel cancels the
		// context runThroughProxy was given.
		run       func(ctx context.Context, cancel context.CancelFunc) error
		wantErr   error
		wantPanic bool
	}{
		{
			name: "success",
			run:  func(context.Context, context.CancelFunc) error { return nil },
		},
		{
			name:    "command error",
			run:     func(context.Context, context.CancelFunc) error { return commandFailure },
			wantErr: commandFailure,
		},
		{
			name: "cancellation",
			run: func(ctx context.Context, cancel context.CancelFunc) error {
				cancel()
				<-ctx.Done()
				return ctx.Err()
			},
			wantErr: context.Canceled,
		},
		{
			name: "SIGTERM",
			run: func(ctx context.Context, _ context.CancelFunc) error {
				if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
					return errors.New("SIGTERM did not cancel the command")
				}
			},
			wantErr: context.Canceled,
		},
		{
			name:      "panic",
			run:       func(context.Context, context.CancelFunc) error { panic("package manager integration bug") },
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var seen proxy.ClientConfig
			manager := &fakeProxyPackageManager{
				runProxied: func(ctx context.Context, command []string, config proxy.ClientConfig) error {
					seen = config
					if strings.Join(command, " ") != "install left-pad" {
						t.Errorf("command = %q, want %q", command, "install left-pad")
					}
					if _, err := os.Stat(config.CACertificatePath); err != nil {
						t.Errorf("CA certificate is not available while the command runs: %v", err)
					}
					return tt.run(ctx, cancel)
				},
			}

			var commandErr, setupErr error
			panicked := func() (panicked bool) {
				defer func() { panicked = recover() != nil }()
				commandErr, setupErr = runThroughProxy(ctx, manager, []string{"install", "left-pad"})
				return false
			}()

			if panicked != tt.wantPanic {
				t.Errorf("runThroughProxy() panicked = %v, want %v", panicked, tt.wantPanic)
			}
			if setupErr != nil {
				t.Errorf("runThroughProxy() setup error = %v, want nil", setupErr)
			}
			if !errors.Is(commandErr, tt.wantErr) {
				t.Errorf("runThroughProxy() command error = %v, want %v", commandErr, tt.wantErr)
			}
			if manager.proxyRunCalls != 1 {
				t.Errorf("RunCommandThroughProxy called %d times, want 1", manager.proxyRunCalls)
			}
			assertProxyStopped(t, seen)
		})
	}
}

func TestRunThroughProxyReportsUpstreamResolutionFailure(t *testing.T) {
	manager := &fakeProxyPackageManager{upstreamErr: errors.New("bad proxy configuration")}

	commandErr, err := runThroughProxy(context.Background(), manager, []string{"install"})
	if err == nil || !strings.Contains(err.Error(), "bad proxy configuration") {
		t.Errorf("runThroughProxy() setup error = %v, want the upstream resolution failure", err)
	}
	if commandErr != nil || manager.proxyRunCalls != 0 {
		t.Errorf("command error %v, RunCommandThroughProxy calls %d; want nil, 0", commandErr, manager.proxyRunCalls)
	}
}

// assertProxyStopped checks that the command received a loopback proxy, that
// the proxy no longer serves requests, and that its CA certificate is gone.
func assertProxyStopped(t *testing.T, config proxy.ClientConfig) {
	t.Helper()
	proxyURL, err := url.Parse(config.URL)
	if err != nil || proxyURL.Hostname() != "127.0.0.1" {
		t.Fatalf("proxy URL = %q, want a loopback URL", config.URL)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   time.Second,
	}
	if response, err := client.Get("http://example.invalid/"); err == nil {
		_ = response.Body.Close()
		t.Error("proxy still serves requests after the command exited")
	}
	if _, err := os.Stat(filepath.Dir(config.CACertificatePath)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("proxy certificate directory still exists: %v", err)
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
				if proxied.proxyRunCalls != 1 || dryRun.resolveCalls != 0 || dryRun.runCalls != 0 {
					t.Errorf("proxy runs %d, resolutions %d, direct runs %d; want 1, 0, 0",
						proxied.proxyRunCalls, dryRun.resolveCalls, dryRun.runCalls)
				}
			} else if proxied.proxyRunCalls != 0 || dryRun.resolveCalls != 1 || dryRun.runCalls != 1 {
				t.Errorf("proxy runs %d, resolutions %d, direct runs %d; want 0, 1, 1",
					proxied.proxyRunCalls, dryRun.resolveCalls, dryRun.runCalls)
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
