//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func init() {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		for _, route := range []string{"http", "https", "authenticated", "mixed-case", "mixed-name", "no-proxy-all"} {
			for _, blocked := range []bool{false, true} {
				key, profile := "pypi-old", "public-pypi"
				if manager == "npm" {
					key, profile = "npm-old", "public-npm"
				}
				action := "allow"
				if blocked {
					action = "block"
				}
				suites["upstream-routing"] = append(suites["upstream-routing"], scenario{
					Scenario: "NET-09", Variant: manager + "-" + route + "-" + action, Manager: manager, Mode: "proxy", Backend: "local",
					RegistryProfile: profile, DiscoveryKey: key, Timeout: 5 * time.Minute,
					Run: func(r *caseRun) error { return runUpstreamRouting(r, route, blocked) },
				})
			}
		}
	}
}

func runUpstreamRouting(r *caseRun, route string, blocked bool) error {
	// Independent caches and installs prevent the native control from warming the
	// protected operation. Both use the same discovered package and public origin.
	native := *r
	native.Root = filepath.Join(r.Root, "native")
	native.WorkDir = filepath.Join(native.Root, "work")
	env, err := isolatedEnvironment(native.Root)
	if err != nil {
		return err
	}
	native.Env = env
	native.Result = &result{Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}
	defer func() {
		r.Result.Commands = append(r.Result.Commands, native.Result.Commands...)
		r.Result.Observations["native"] = native.Result.Observations
		for key, value := range native.Result.Evidence {
			r.Result.Evidence["native-"+key] = value
		}
	}()
	if err := routingPhase(&native, route, false, false); err != nil {
		return fmt.Errorf("native control: %w", err)
	}
	return routingPhase(r, route, true, blocked)
}

func routingPhase(r *caseRun, route string, protected, blocked bool) (returnErr error) {
	allowed := []string{"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "api.osv.dev", "raw.githubusercontent.com"}
	selected, err := newForwardProxy(route == "https", route == "authenticated", allowed)
	if err != nil {
		return err
	}
	defer selected.close()
	alternative, err := newForwardProxy(false, false, allowed)
	if err != nil {
		return err
	}
	defer alternative.close()
	label := "native"
	if protected {
		label = "scfw"
	}
	defer func() {
		path := filepath.Join(r.Root, "routes-"+label+".json")
		evidence := map[string]any{"selected": selected.snapshot(), "alternative": alternative.snapshot()}
		if err := writeJSON(path, evidence); err != nil {
			returnErr = errors.Join(returnErr, err)
		} else {
			returnErr = errors.Join(returnErr, r.Keep("routes-"+label, path))
		}
	}()
	settings := map[string]string{"HTTPS_PROXY": selected.URL(), "HTTP_PROXY": selected.URL()}
	if route == "mixed-case" {
		settings["HTTPS_PROXY"] = alternative.URL()
		settings["https_proxy"] = selected.URL()
		if r.Cell.Manager == "uv" {
			settings["HTTPS_PROXY"], settings["https_proxy"] = selected.URL(), alternative.URL()
		}
	}
	if route == "mixed-name" {
		delete(settings, "HTTPS_PROXY")
		settings["hTtPs_PrOxY"] = selected.URL()
	}
	if route == "no-proxy-all" {
		settings["NO_PROXY"] = "*"
	}
	maps.Copy(r.Env, settings)
	// Keep the concrete selected input without persisting proxy credentials.
	redacted := maps.Clone(settings)
	for key, value := range redacted {
		if u, err := url.Parse(value); err == nil && u.User != nil {
			u.User = url.User("redacted")
			redacted[key] = u.String()
		}
	}
	r.Result.Observations["routing_environment"] = redacted
	var bundle string
	var original []byte
	if route == "https" {
		var err error
		bundle, original, err = routingCABundle(r, selected.certificate())
		if err != nil {
			return err
		}
		r.Env["SSL_CERT_FILE"] = bundle // Also trust the forwarding proxy for live Go verifier clients.
		switch r.Cell.Manager {
		case "npm":
			r.Env["NODE_EXTRA_CA_CERTS"] = bundle
		case "pip", "poetry":
			r.Env["REQUESTS_CA_BUNDLE"] = bundle
		}
	}
	var command commandEvidence
	if protected {
		switch r.Cell.Manager {
		case "npm":
			err = runNPMBaseline(r, npmOptions{proxy: "1", block: blocked})
		case "pip":
			err = runPipBaseline(r, pipOptions{proxy: "1", block: blocked})
		case "poetry":
			err = runPoetryBaseline(r, poetryOptions{proxy: "1", block: blocked, operation: "install"})
		case "uv":
			err = runUVBaseline(r, uvOptions{flag: "1", block: blocked, operation: "pip"})
		}
		for _, item := range r.Result.Commands {
			if len(item.Argv) > 0 && item.Argv[0] == r.Binary {
				command = item
			}
		}
	} else {
		command, err = nativeRoutingInstall(r)
	}
	if err != nil {
		return err
	}
	if command.StartedAt.IsZero() {
		return fmt.Errorf("missing installation command evidence")
	}
	for key, want := range settings {
		if r.Env[key] != want {
			return fmt.Errorf("parent routing setting changed: %s", key)
		}
	}
	if bundle != "" {
		after, err := os.ReadFile(bundle)
		if err != nil {
			return err
		}
		if !bytes.Equal(after, original) {
			return fmt.Errorf("original CA bundle changed")
		}
		if err := r.Keep("original-ca-bundle", bundle); err != nil {
			return err
		}
	}
	registry := "pypi.org"
	if r.Cell.Manager == "npm" {
		registry = "registry.npmjs.org"
	}
	hosts := []string{registry}
	if !protected || !blocked {
		artifactURL, err := url.Parse(r.Candidate.Artifacts[0].URL)
		if err != nil {
			return err
		}
		hosts = append(hosts, artifactURL.Hostname())
	}
	expected := (route != "no-proxy-all" || r.Cell.Manager == "npm") && (route != "mixed-name" || r.Cell.Manager != "uv")
	for _, host := range hosts {
		if err := assertForwardRoute(selected.snapshot(), command, host, expected); err != nil {
			return fmt.Errorf("selected upstream: %w", err)
		}
		if err := assertForwardRoute(alternative.snapshot(), command, host, false); err != nil {
			return err
		}
	}
	return nil
}

func assertForwardRoute(routes []forwardRoute, command commandEvidence, host string, expected bool) error {
	found := false
	for _, route := range routes {
		if route.At.Before(command.StartedAt) || route.At.After(command.EndedAt) || strings.Split(route.Authority, ":")[0] != host {
			continue
		}
		if !route.Authorized || route.Error != "" {
			return fmt.Errorf("upstream rejected required route: %+v", route)
		}
		found = true
	}
	if found != expected {
		return fmt.Errorf("registry %s routed=%v, expected %v", host, found, expected)
	}
	return nil
}

func routingCABundle(r *caseRun, certificate []byte) (string, []byte, error) {
	fixture := "roots.py"
	if r.Cell.Manager == "npm" {
		fixture = "roots.cjs"
	}
	script, err := filepath.Abs(filepath.Join("testdata/upstream_routing", fixture))
	if err != nil {
		return "", nil, err
	}
	command, err := r.Command("native-trust-roots", r.Cell.Runtime, script)
	if err != nil {
		return "", nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	roots, err := os.ReadFile(command.Stdout.Path)
	if err != nil {
		return "", nil, err
	}
	if !bytes.Contains(roots, []byte("-----BEGIN CERTIFICATE-----")) {
		return "", nil, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("native runtime supplied no trust roots"))
	}
	bundle := append(append(roots, '\n'), certificate...)
	path := filepath.Join(r.Root, "forwarding-ca.pem")
	return path, bundle, os.WriteFile(path, bundle, 0600)
}

func nativeRoutingInstall(r *caseRun) (commandEvidence, error) {
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	var args []string
	var python string
	target := filepath.Join(r.Root, "installed")
	switch r.Cell.Manager {
	case "npm":
		if _, err := prepareNPMProject(r); err != nil {
			return commandEvidence{}, err
		}
		args = []string{"install", r.Candidate.Project + "@" + r.Candidate.Version, "--ignore-scripts", "--no-audit", "--no-fund"}
	case "pip":
		args = []string{"install", "--no-deps", "--only-binary=:all:", "--target", target, r.Candidate.Project + "==" + r.Candidate.Version}
	case "poetry":
		var err error
		python, err = preparePoetry(r, "install")
		if err != nil {
			return commandEvidence{}, err
		}
		args = []string{"--no-interaction", "install"}
	case "uv":
		if _, _, err := prepareUV(r, uvOptions{}); err != nil {
			return commandEvidence{}, err
		}
		venv := filepath.Join(r.Root, "venv")
		if _, err := r.Command("native-venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
			return commandEvidence{}, classified("INFRASTRUCTURE_FAILURE", err)
		}
		python = filepath.Join(venv, "bin", "python")
		args = []string{"pip", "install", "--python", python, r.Candidate.Project + "==" + r.Candidate.Version}
	}
	command, err := r.Command("native-install", append([]string{r.Cell.Executable}, args...)...)
	if err != nil {
		return command, err
	}
	switch r.Cell.Manager {
	case "npm":
		err = assertNPMInstall(r, false)
	case "pip":
		script, pathErr := filepath.Abs("testdata/pip_baseline/inspect_install.py")
		if pathErr != nil {
			return command, pathErr
		}
		state, stateErr := r.Command("native-installed-state", r.Cell.Runtime, "-I", script, target, r.Candidate.Project, r.Candidate.Module)
		if stateErr != nil {
			return command, stateErr
		}
		var installed struct {
			Present  bool
			Version  string
			Imported bool
		}
		if err = readJSON(state.Stdout.Path, &installed); err == nil && (!installed.Present || !installed.Imported || installed.Version != r.Candidate.Version) {
			err = fmt.Errorf("native pip did not install exact candidate: %+v", installed)
		}
		r.Result.Observations["installed"] = installed
	default:
		err = assertUVInstalled(r, python, r.Candidate.Version, "native-installed")
	}
	return command, err
}

func TestHarnessForwardRouteEvidence(t *testing.T) {
	start := time.Now().UTC()
	command := commandEvidence{StartedAt: start, EndedAt: start.Add(time.Second)}
	route := forwardRoute{At: start.Add(time.Millisecond), Authority: "pypi.org:443", Authorized: true}
	if err := assertForwardRoute([]forwardRoute{route}, command, "pypi.org", true); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []forwardRoute{
		{At: start.Add(-time.Second), Authority: route.Authority, Authorized: true},
		{At: route.At, Authority: "api.osv.dev:443", Authorized: true},
		{At: route.At, Authority: route.Authority, Authorized: false},
		{At: route.At, Authority: route.Authority, Authorized: true, Error: "failed"},
	} {
		if err := assertForwardRoute([]forwardRoute{changed}, command, "pypi.org", true); err == nil {
			t.Fatalf("accepted irrelevant/failed evidence: %+v", changed)
		}
	}
	if err := assertForwardRoute([]forwardRoute{route}, command, "pypi.org", false); err == nil {
		t.Fatal("accepted bypass using upstream")
	}
}
func TestHarnessUpstreamRoutingInventory(t *testing.T) {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		planned, err := selectCases(cell{ID: "routing", Manager: manager, Modes: []string{"proxy"}, Suites: []string{"upstream-routing"}}, []string{"upstream-routing"})
		if err != nil {
			t.Fatal(err)
		}
		applicable := slices.DeleteFunc(planned, func(p plannedCase) bool { return p.NotApplicable != "" })
		if len(applicable) != 12 {
			t.Fatalf("%s: expected 12 runnable variants, got %d", manager, len(applicable))
		}
	}
}
