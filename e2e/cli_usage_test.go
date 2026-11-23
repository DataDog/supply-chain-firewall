//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type usageCase struct {
	name, diagnostic, environment, value string
	args                                 []string
}

func usageCases(manager string) []usageCase {
	command := []string{"--", manager, "install", "scfw-e2e-must-not-fetch"}
	if manager == "uv" {
		command = []string{"--", manager, "pip", "install", "scfw-e2e-must-not-fetch"}
	}
	if manager == "poetry" {
		command = []string{"--", manager, "add", "scfw-e2e-must-not-fetch"}
	}
	return []usageCase{
		{name: "missing-separator", diagnostic: `missing "--" separator`, args: []string{manager}},
		{name: "empty-command", diagnostic: "no command specified", args: []string{"--"}},
		{name: "before-separator", diagnostic: "unexpected argument", args: append([]string{"unexpected"}, command...)},
		{name: "unknown-command", diagnostic: "unsupported command", args: []string{"--", "scfw-e2e-unknown-manager"}},
		{name: "bad-executable", diagnostic: "does-not-exist", args: append([]string{"--executable", "/scfw-e2e-does-not-exist"}, command...)},
		{name: "conflicting-warning-flags", diagnostic: "none of the others can be", args: append([]string{"--allow-on-warning", "--block-on-warning"}, command...)},
		{name: "unknown-flag", diagnostic: "unknown flag", args: []string{"--scfw-e2e-unknown"}},
		{name: "missing-executable-value", diagnostic: "flag needs an argument", args: []string{"--executable"}},
		{name: "flag-like-executable", diagnostic: "looks like another flag", args: append([]string{"--executable=--bad"}, command...)},
		{name: "invalid-mode", diagnostic: "invalid SCFW_MODE", environment: "SCFW_MODE", value: "not-a-mode", args: command},
		{name: "invalid-warning", diagnostic: "invalid SCFW_ON_WARNING", environment: "SCFW_ON_WARNING", value: "not-an-action", args: command},
	}
}
func init() {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		for _, mode := range []string{"resolution", "proxy"} {
			if manager == "uv" && mode == "resolution" {
				continue
			}
			for _, option := range usageCases(manager) {
				suites["cli-usage"] = append(suites["cli-usage"], scenario{Scenario: "CORE-09", Variant: manager + "-" + mode + "-" + option.name, Manager: manager, Mode: mode, Backend: "local", RegistryProfile: "loopback-no-request-tripwire", Timeout: 30 * time.Second, Run: func(r *caseRun) error { return runUsageCase(r, option) }})
			}
		}
	}
}
func runUsageCase(r *caseRun, option usageCase) error {
	// Invalid CLI input must fail before any manager or registry operation. The
	// loopback registry makes an accidental request observable, without a public
	// request for a deliberately nonexistent package.
	var mu sync.Mutex
	var requests []string
	var unexpected int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, req.Method+" "+req.URL.String())
		// SCFW may initialize its malware dataset before the bad executable fails.
		// Only that metadata connection is outside the no-package-request oracle.
		if req.Method != http.MethodConnect || req.Host != "raw.githubusercontent.com:443" {
			unexpected++
		}
		http.Error(w, "unexpected registry request", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	r.Env["npm_config_registry"] = server.URL
	r.Env["PIP_INDEX_URL"] = server.URL
	r.Env["UV_DEFAULT_INDEX"] = server.URL
	r.Env["HTTP_PROXY"], r.Env["HTTPS_PROXY"] = server.URL, server.URL
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	if option.environment != "" {
		r.Env[option.environment] = option.value
	}
	before, err := os.ReadDir(r.WorkDir)
	if err != nil {
		return err
	}
	ev, runErr := r.Command("invalid-usage", append([]string{r.Binary, "run"}, option.args...)...)
	if ev.TimedOut || ev.Signal != "" || ev.ExitCode <= 0 || (option.name != "bad-executable" && ev.ExitCode != 1) {
		return fmt.Errorf("usage exit=%d signal=%s: %v", ev.ExitCode, ev.Signal, runErr)
	}
	out, err := os.ReadFile(ev.Stderr.Path)
	if err != nil {
		return err
	}
	diagnostic := option.diagnostic
	if option.name == "bad-executable" && r.Cell.Manager == "pip" && r.Spec.Mode == "proxy" {
		diagnostic = "could not determine pip proxy compatibility"
	}
	if !strings.Contains(string(out), diagnostic) {
		return fmt.Errorf("missing %q diagnostic: %s", diagnostic, out)
	}
	mu.Lock()
	defer mu.Unlock()
	r.Result.Observations["network_requests"] = requests
	if unexpected != 0 {
		return fmt.Errorf("invalid usage made unexpected requests: %v", requests)
	}
	after, err := os.ReadDir(r.WorkDir)
	if err != nil {
		return err
	}
	if len(before) != 0 || len(after) != 0 {
		return fmt.Errorf("invalid usage modified its empty project")
	}
	if _, err := os.Stat(r.Env["SCFW_LOG_FILE"]); !os.IsNotExist(err) {
		return fmt.Errorf("invalid usage unexpectedly produced policy report: %v", err)
	}
	r.Result.PolicyOutcome = "NOT_OBSERVED"
	r.Result.ResolvedAction = "REJECTED_USAGE"
	r.Result.Observations["package_registry_requests"] = unexpected
	r.Result.Observations["diagnostic"] = option.diagnostic
	return nil
}
