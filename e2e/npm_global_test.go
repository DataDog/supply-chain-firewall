//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"
)

func init() {
	for _, mode := range []string{"resolution", "proxy"} {
		for _, variant := range []string{"global-workspace-member", "global-self"} {
			for _, block := range []bool{false, true} {
				capability := "npm-projects-v7"
				if variant == "global-self" {
					capability = "npm-install-links-v8.8"
				}
				suites["npm-projects"] = append(suites["npm-projects"], scenario{Scenario: "NPM-03", Variant: mode + "-" + variant + map[bool]string{false: "-allow", true: "-block"}[block], Manager: "npm", Mode: mode, Backend: "local", RegistryProfile: "public-npm", DiscoveryKey: "npm-projects", Capabilities: []string{capability}, Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runNPMProject(r, npmProjectOptions{variant, block}) }})
			}
		}
	}
}

func npmGlobalVariant(variant string) bool {
	return variant == "global-workspace-member" || variant == "global-self"
}

func npmGlobalFiles(r *caseRun, variant string, direct, leaf candidate) (map[string]json.RawMessage, error) {
	tmpl, err := template.ParseFiles("testdata/npm_global/projects.json.tmpl")
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err := tmpl.Execute(&body, map[string]any{"Direct": direct, "Leaf": leaf}); err != nil {
		return nil, err
	}
	var fixtures map[string]map[string]json.RawMessage
	if err := json.Unmarshal(body.Bytes(), &fixtures); err != nil {
		return nil, err
	}
	files := fixtures[variant]
	if len(files) == 0 {
		return nil, fmt.Errorf("unknown global project %s", variant)
	}
	for path, body := range files {
		destination := filepath.Join(r.WorkDir, path)
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(destination, body, 0600); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func prepareNPMGlobalState(r *caseRun, variant string, target candidate) error {
	if variant == "global-workspace-member" {
		command, err := r.Command("global-member-bootstrap", r.Cell.Executable, "install", "--ignore-scripts", "--loglevel=http")
		if err != nil {
			return classified("INFRASTRUCTURE_FAILURE", err)
		}
		var installed struct {
			Version string `json:"version"`
		}
		path := filepath.Join(r.WorkDir, "packages/member/node_modules", target.Project, "package.json")
		if err := readJSON(path, &installed); err != nil {
			return err
		}
		if installed.Version != target.Version {
			return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("member must already contain the exact global target"))
		}
		log, err := os.ReadFile(command.Stderr.Path)
		if err != nil {
			return err
		}
		if !bytes.Contains(log, []byte(target.Artifacts[0].URL)) {
			return fmt.Errorf("member bootstrap lacks real target artifact download")
		}
		r.Result.Observations["member_bootstrap_artifact_"+filepath.Base(r.Root)] = target.Artifacts[0]
	}
	// Preserve bootstrap files/cache as evidence, but require native and wrapped
	// final commands to fetch from the registry with equivalent fresh caches.
	r.Env["npm_config_cache"] = filepath.Join(r.Root, "cache", "npm-global-final")
	r.Env["npm_config_prefix"] = filepath.Join(r.Root, "global-prefix")
	return os.MkdirAll(filepath.Join(r.Env["npm_config_prefix"], "lib", "node_modules"), 0700)
}

func npmGlobalArgs(variant string, target candidate) []string {
	if variant == "global-self" {
		return []string{"-g", "--install-links"}
	}
	return []string{"-g", target.Project + "@" + target.Version}
}

func TestHarnessNPMGlobalSelfCapability(t *testing.T) {
	c := cell{ID: "npm7", Manager: "npm", ManagerVersion: "7.0.0", Modes: []string{"resolution", "proxy"}, Suites: []string{"npm-projects"}, Capabilities: []string{"npm-projects-v7"}}
	for _, supported := range []bool{false, true} {
		if supported {
			c.Capabilities = append(c.Capabilities, "npm-install-links-v8.8")
		}
		cases, err := selectCases(c, []string{"npm-projects"})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, item := range cases {
			if strings.Contains(item.Variant, "-global-self-") {
				count++
				if (item.NotApplicable == "") != supported {
					t.Fatalf("incorrect install-links applicability: %+v", item)
				}
			}
		}
		if count != 4 {
			t.Fatalf("self variants=%d, want4", count)
		}
	}
}
