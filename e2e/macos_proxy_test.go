//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() {
	for _, manager := range []string{"pip", "poetry"} {
		for _, route := range []string{"system", "artifact-bypass", "environment", "no-proxy-only"} {
			for _, blocked := range []bool{false, true} {
				action := "allow"
				if blocked {
					action = "block"
				}
				suites["macos-proxy"] = append(suites["macos-proxy"], scenario{
					Scenario: "NET-15", Variant: manager + "-" + route + "-" + action, Manager: manager,
					Mode: "proxy", Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "pypi-old",
					Capabilities: []string{"macos-system-proxy"}, Timeout: 10 * time.Minute,
					Run: func(r *caseRun) error { return runMacOSProxy(r, route, blocked) },
				})
			}
		}
	}
}

func macOSProxyGuard(osName, actions, disposable, service string) error {
	if osName != "darwin" || actions != "true" || disposable != "1" || service == "" {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("macos-proxy requires native macOS, GITHUB_ACTIONS=true, SCFW_E2E_DISPOSABLE_MACOS=1 and SCFW_E2E_MACOS_SERVICE set to the active network service ID"))
	}
	return nil
}

// This lock is also the contract for other native network/keychain fixtures.
// Never unlink it: removing a held advisory lock permits a second inode/owner.
func lockMacOSSettings(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another native settings fixture holds %s: %w", path, err)
	}
	return file, nil
}

func runMacOSProxy(r *caseRun, route string, blocked bool) (returnErr error) {
	service := os.Getenv("SCFW_E2E_MACOS_SERVICE")
	if err := macOSProxyGuard(runtime.GOOS, os.Getenv("GITHUB_ACTIONS"), os.Getenv("SCFW_E2E_DISPOSABLE_MACOS"), service); err != nil {
		return err
	}
	// Compile as the ordinary runner user. Only the bounded settings operations
	// use sudo; the package managers and SCFW retain their isolated environments.
	source, err := filepath.Abs("testdata/macos_proxy/settings.swift")
	if err != nil {
		return err
	}
	fixture := filepath.Join(r.Root, "native-proxy-settings")
	for _, command := range []struct {
		label string
		argv  []string
	}{
		{"sudo-capability", []string{"/usr/bin/sudo", "-n", "/usr/bin/true"}},
		{"xcode-version", []string{"/usr/bin/xcodebuild", "-version"}},
		{"swift-version", []string{"/usr/bin/xcrun", "swiftc", "--version"}},
		{"compile-settings", []string{"/usr/bin/xcrun", "swiftc", "-module-cache-path", filepath.Join(r.Root, "swift-cache"), source, "-o", fixture}},
	} {
		if _, err := r.Command(command.label, command.argv...); err != nil {
			return classified("INFRASTRUCTURE_FAILURE", err)
		}
	}
	lock, err := lockMacOSSettings("/var/tmp/scfw-e2e-system-settings.lock")
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	defer lock.Close()
	allowed := []string{"pypi.org", "files.pythonhosted.org", "api.osv.dev", "raw.githubusercontent.com"}
	system, err := newForwardProxy(false, false, allowed)
	if err != nil {
		return err
	}
	defer system.close()
	environment, err := newForwardProxy(false, false, allowed)
	if err != nil {
		return err
	}
	defer environment.close()
	defer func() {
		path := filepath.Join(r.Root, "native-routes.json")
		if err := writeJSON(path, map[string]any{"system": system.snapshot(), "environment": environment.snapshot()}); err != nil {
			returnErr = errors.Join(returnErr, err)
		} else {
			returnErr = errors.Join(returnErr, r.Keep("native-routes", path))
		}
	}()
	snapshot, err := r.Command("system-before", "/usr/bin/sudo", "-n", fixture, "snapshot", service)
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	// Restoration is armed before the first mutation. A timed-out test still
	// gets an independent bounded context, and a restore/verification failure
	// always fails the case. Restore verifies stored AND effective dictionaries.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cleanup := *r
		cleanup.Context = ctx
		_, err := cleanup.Command("system-restore-verified", "/usr/bin/sudo", "-n", fixture, "restore", service, snapshot.Stdout.Path)
		r.Result.Observations["system_settings_restored"] = err == nil
		if err != nil {
			returnErr = errors.Join(returnErr, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("restore native proxy settings: %w", err)))
		}
	}()
	artifactURL, err := url.Parse(r.Candidate.Artifacts[0].URL)
	if err != nil {
		return err
	}
	bypass := ""
	if route == "artifact-bypass" {
		bypass = artifactURL.Hostname()
	}
	if _, err := r.Command("system-apply-verified", "/usr/bin/sudo", "-n", fixture, "apply", service, system.URL(), bypass); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	r.Result.Observations["native_proxy"] = map[string]string{"service_id": service, "system_proxy": system.URL(), "environment_proxy": environment.URL(), "system_bypass": bypass}

	native := *r
	native.Root = filepath.Join(r.Root, "native")
	native.WorkDir = filepath.Join(native.Root, "work")
	native.Env, err = isolatedEnvironment(native.Root)
	if err != nil {
		return err
	}
	native.Result = &result{Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}
	defer func() {
		r.Result.Commands = append(r.Result.Commands, native.Result.Commands...)
		r.Result.Observations["native"] = native.Result.Observations
		for key, value := range native.Result.Evidence {
			r.Result.Evidence["native-"+key] = value
		}
	}()
	if err := macOSProxyPhase(&native, route, false, false, system, environment); err != nil {
		return fmt.Errorf("native control: %w", err)
	}
	return macOSProxyPhase(r, route, true, blocked, system, environment)
}

func macOSProxyPhase(r *caseRun, route string, protected, blocked bool, system, environment *forwardProxy) error {
	for key := range r.Env {
		if strings.HasSuffix(strings.ToLower(key), "_proxy") {
			return fmt.Errorf("unexpected ambient proxy setting %s", key)
		}
	}
	switch route {
	case "environment":
		r.Env["HTTPS_PROXY"], r.Env["HTTP_PROXY"] = environment.URL(), environment.URL()
	case "no-proxy-only":
		// Even a nonmatching NO_PROXY populates urllib's environment map and
		// suppresses native discovery. It must not suppress SCFW inspection.
		r.Env["NO_PROXY"] = "does-not-match.invalid"
	}
	var command commandEvidence
	var err error
	if !protected {
		command, err = nativeRoutingInstall(r)
	} else {
		if r.Cell.Manager == "pip" {
			err = runPipBaseline(r, pipOptions{proxy: "1", block: blocked})
		} else {
			err = runPoetryBaseline(r, poetryOptions{proxy: "1", block: blocked, operation: "install"})
		}
		for _, item := range r.Result.Commands {
			if len(item.Argv) > 0 && item.Argv[0] == r.Binary {
				command = item
			}
		}
	}
	if err != nil {
		return err
	}
	if command.StartedAt.IsZero() {
		return fmt.Errorf("missing installation command evidence")
	}
	artifactURL, err := url.Parse(r.Candidate.Artifacts[0].URL)
	if err != nil {
		return err
	}
	if blocked {
		if err := assertMacOSArtifactDenied(r, command); err != nil {
			return err
		}
	}
	return assertMacOSProxyRoutes(route, blocked, command, artifactURL.Hostname(), system.snapshot(), environment.snapshot())
}

func assertMacOSProxyRoutes(route string, blocked bool, command commandEvidence, artifactHost string, system, environment []forwardRoute) error {
	for _, host := range []string{"pypi.org", artifactHost} {
		systemExpected, envExpected := macOSExpectedRoute(route, host == artifactHost)
		for _, recorder := range []struct {
			name     string
			routes   []forwardRoute
			expected bool
		}{{"system", system, systemExpected}, {"environment", environment, envExpected}} {
			// PEP 658 metadata may use the selected artifact host before the
			// wheel is blocked. Its presence is optional; forbidden routes
			// remain forbidden, and the manager must observe an exact-wheel 403.
			if blocked && host == artifactHost && recorder.expected {
				continue
			}
			if err := assertForwardRoute(recorder.routes, command, host, recorder.expected); err != nil {
				return fmt.Errorf("%s proxy: %w", recorder.name, err)
			}
		}
	}
	return nil
}

func macOSExpectedRoute(route string, artifact bool) (system, environment bool) {
	switch route {
	case "system":
		return true, false
	case "artifact-bypass":
		return !artifact, false
	case "environment":
		return false, true
	default:
		return false, false
	}
}

func assertMacOSArtifactDenied(r *caseRun, command commandEvidence) error {
	for _, evidence := range []fileEvidence{command.Stdout, command.Stderr} {
		output, err := os.ReadFile(evidence.Path)
		if err != nil {
			return err
		}
		if macOSArtifactDenial(string(output), r.Candidate.Artifacts[0].URL) {
			r.Result.Observations["denied_artifact"] = map[string]any{"url": r.Candidate.Artifacts[0].URL, "manager_http_status": 403}
			return nil
		}
	}
	return fmt.Errorf("manager did not observe HTTP 403 for the exact discovered distribution")
}

func macOSArtifactDenial(output, artifactURL string) bool {
	for _, line := range strings.Split(output, "\n") {
		_, target, found := strings.Cut(line, "403 Client Error: Forbidden for url: ")
		if !found {
			continue
		}
		// pip may append installation context after the URL; Poetry may add
		// an integrity fragment. Registry URLs cannot contain literal spaces.
		fields := strings.Fields(target)
		if len(fields) == 0 {
			continue
		}
		parsed, err := url.Parse(fields[0])
		if err != nil {
			continue
		}
		parsed.Fragment, parsed.RawFragment = "", ""
		if parsed.String() == artifactURL {
			return true
		}
	}
	return false
}

func TestHarnessMacOSProxyInventory(t *testing.T) {
	for _, manager := range []string{"pip", "poetry"} {
		for _, osName := range []string{"darwin", "linux"} {
			c := cell{ID: "native", OS: osName, Manager: manager, Modes: []string{"proxy"}, Suites: []string{"macos-proxy", "upstream-routing"}}
			if osName == "darwin" {
				c.Capabilities = []string{"macos-system-proxy"}
			}
			cases, err := selectCases(c, c.Suites)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, spec := range cases {
				if spec.Suite == "macos-proxy" && spec.NotApplicable == "" {
					count++
				}
			}
			want := 0
			if osName == "darwin" {
				want = 8
			}
			if count != want {
				t.Fatalf("%s/%s: %d applicable, want %d", osName, manager, count, want)
			}
		}
	}
}

func TestHarnessMacOSSettingsGuardAndLock(t *testing.T) {
	if err := macOSProxyGuard("darwin", "true", "1", "service-id"); err != nil {
		t.Fatal(err)
	}
	for _, inputs := range [][4]string{{"linux", "true", "1", "service-id"}, {"darwin", "", "1", "service-id"}, {"darwin", "true", "", "service-id"}, {"darwin", "true", "1", ""}} {
		if err := macOSProxyGuard(inputs[0], inputs[1], inputs[2], inputs[3]); err == nil {
			t.Fatal("accepted unsafe native settings mutation")
		}
	}
	path := filepath.Join(t.TempDir(), "settings.lock")
	first, err := lockMacOSSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockMacOSSettings(path); err == nil {
		_ = second.Close()
		t.Fatal("accepted concurrent native settings owner")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := lockMacOSSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
}

// A blocked wheel can be preceded by a PEP 658 metadata request on the same
// host. A CONNECT recorder cannot distinguish those paths inside the tunnel.
func TestHarnessMacOSBlockedMetadata(t *testing.T) {
	start := time.Now().UTC()
	command := commandEvidence{StartedAt: start, EndedAt: start.Add(time.Second)}
	registry := forwardRoute{At: start.Add(time.Millisecond), Authority: "pypi.org:443", Authorized: true}
	metadata := forwardRoute{At: start.Add(2 * time.Millisecond), Authority: "files.pythonhosted.org:443", Authorized: true}
	for _, routes := range [][]forwardRoute{{registry}, {registry, metadata}} {
		if err := assertMacOSProxyRoutes("system", true, command, "files.pythonhosted.org", routes, nil); err != nil {
			t.Fatalf("valid blocked control with optional metadata: %v", err)
		}
		if err := assertMacOSProxyRoutes("environment", true, command, "files.pythonhosted.org", nil, routes); err != nil {
			t.Fatal(err)
		}
	}
	if err := assertMacOSProxyRoutes("system", true, command, "files.pythonhosted.org", []forwardRoute{metadata}, nil); err == nil {
		t.Fatal("missing registry route accepted")
	}
	if err := assertMacOSProxyRoutes("system", true, command, "files.pythonhosted.org", []forwardRoute{registry}, []forwardRoute{metadata}); err == nil {
		t.Fatal("metadata on competing route accepted")
	}
	if err := assertMacOSProxyRoutes("system", false, command, "files.pythonhosted.org", []forwardRoute{registry}, nil); err == nil {
		t.Fatal("missing allowed artifact route accepted")
	}
}

func TestHarnessMacOSArtifactDenial(t *testing.T) {
	var cases map[string]struct {
		Output string `json:"output"`
		Denied bool   `json:"denied"`
	}
	if err := readJSON("testdata/macos_proxy/responses.json", &cases); err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		if got := macOSArtifactDenial(c.Output, "https://files.pythonhosted.org/packages/fixture.whl"); got != c.Denied {
			t.Errorf("%s: denied=%v, want %v", name, got, c.Denied)
		}
	}
}
