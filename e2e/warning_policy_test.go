//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import "time"

type localPolicyOptions struct {
	name, scenario, outcome, flag, environment string
	lists                                      []string
	findings                                   map[string]string
	allowWarning, reportFailure, invalid       bool
}

func localPolicyCases() []localPolicyOptions {
	critical := map[string]string{"exact-critical": "CRITICAL"}
	warning := map[string]string{"exact-warning": "WARNING"}
	cases := []localPolicyOptions{
		{name: "no-list", scenario: "LOCAL-02", outcome: "ALLOW"},
		{name: "exact-critical", scenario: "LOCAL-01", lists: []string{"exact-critical"}, outcome: "BLOCK", findings: critical},
		{name: "version-mismatch", scenario: "LOCAL-01", lists: []string{"mismatch"}, outcome: "ALLOW"},
		{name: "wildcard", scenario: "LOCAL-01", lists: []string{"wildcard"}, outcome: "BLOCK", findings: map[string]string{"wildcard": "CRITICAL"}},
		{name: "all-versions", scenario: "LOCAL-01", lists: []string{"all-versions"}, outcome: "BLOCK", findings: map[string]string{"all-versions": "CRITICAL"}},
		{name: "empty-versions", scenario: "LOCAL-01", lists: []string{"empty-versions"}, outcome: "BLOCK", findings: map[string]string{"empty-versions": "CRITICAL"}},
		{name: "case-insensitive-severity-ecosystem", scenario: "LOCAL-01", lists: []string{"case-insensitive"}, outcome: "BLOCK", findings: map[string]string{"case-insensitive": "CRITICAL"}},
		{name: "multiple-lists", scenario: "LOCAL-02", lists: []string{"exact-warning", "exact-critical"}, outcome: "BLOCK", findings: map[string]string{"exact-warning": "WARNING", "exact-critical": "CRITICAL"}},
		{name: "malformed-only", scenario: "LOCAL-02", lists: []string{"malformed"}, outcome: "ALLOW", invalid: true},
		{name: "invalid-severity-only", scenario: "LOCAL-02", lists: []string{"invalid-severity"}, outcome: "ALLOW", invalid: true},
		{name: "malformed-with-valid", scenario: "LOCAL-02", lists: []string{"malformed", "exact-critical"}, outcome: "BLOCK", findings: critical, invalid: true},
		{name: "invalid-severity-with-valid", scenario: "LOCAL-02", lists: []string{"invalid-severity", "exact-warning"}, outcome: "WARN", findings: warning, invalid: true},
		{name: "unwritable-report-allow", scenario: "CORE-08", outcome: "ALLOW", reportFailure: true},
		{name: "unwritable-report-block", scenario: "CORE-08", lists: []string{"exact-critical"}, outcome: "BLOCK", findings: critical, reportFailure: true},
	}
	for _, option := range []struct {
		name, flag, environment string
		allow                   bool
	}{
		{name: "default"},
		{name: "allow-flag", flag: "--allow-on-warning", allow: true},
		{name: "block-flag", flag: "--block-on-warning"},
		{name: "allow-env", environment: "allow", allow: true},
		{name: "block-env", environment: "block"},
		{name: "env-allow-overrides-block", flag: "--block-on-warning", environment: "ALLOW", allow: true},
		{name: "env-block-overrides-allow", flag: "--allow-on-warning", environment: "BLOCK"},
	} {
		cases = append(cases, localPolicyOptions{name: "warning-" + option.name, scenario: "CORE-05", lists: []string{"exact-warning"}, outcome: "WARN", findings: warning, flag: option.flag, environment: option.environment, allowWarning: option.allow})
	}
	cases = append(cases, localPolicyOptions{name: "critical-unaffected-by-warning-allow", scenario: "CORE-05", lists: []string{"exact-critical"}, outcome: "BLOCK", findings: critical, flag: "--allow-on-warning", environment: "allow", allowWarning: true})
	return cases
}

func init() {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		for _, mode := range []string{"resolution", "proxy"} {
			if manager == "uv" && mode == "resolution" {
				continue
			}
			for _, options := range localPolicyCases() {
				key, profile := "pypi-old", "public-pypi"
				if manager == "npm" {
					key, profile = "npm-old", "public-npm"
				}
				suites["local-policy"] = append(suites["local-policy"], scenario{Scenario: options.scenario, Variant: manager + "-" + mode + "-" + options.name, Manager: manager, Mode: mode, Backend: "local", RegistryProfile: profile, DiscoveryKey: key, Timeout: 4 * time.Minute, Run: func(r *caseRun) error { return runLocalPolicy(r, options) }})
			}
		}
	}
}
