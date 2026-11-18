//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type npmOptions struct {
	alias, proxy                  string
	block, errorOnBlock, explicit bool
}

func init() {
	add := func(id, variant, mode, key string, options npmOptions) {
		var capabilities []string
		if options.alias == "isntall" {
			capabilities = []string{"npm-alias-isntall-install"}
		}
		suites["npm-baseline"] = append(suites["npm-baseline"], scenario{Scenario: id, Variant: variant, Manager: "npm", Mode: mode, Backend: "local", RegistryProfile: "public-npm", DiscoveryKey: key, Capabilities: capabilities, Timeout: 3 * time.Minute, Run: func(r *caseRun) error { return runNPMBaseline(r, options) }})
	}
	for _, mode := range []string{"resolution", "proxy"} {
		proxy := ""
		if mode == "proxy" {
			proxy = "1"
		}
		add("CORE-01", mode+"-allow", mode, "npm-old", npmOptions{proxy: proxy})
		add("CORE-02", mode+"-block-default", mode, "npm-old", npmOptions{proxy: proxy, block: true})
		add("CORE-02", mode+"-block-error", mode, "npm-old", npmOptions{proxy: proxy, block: true, errorOnBlock: true})
		add("CORE-12", mode+"-explicit-spaces", mode, "npm-old", npmOptions{proxy: proxy, explicit: true})
		for _, block := range []bool{false, true} {
			outcome := "allow"
			if block {
				outcome = "block"
			}
			add("REPORT-01", mode+"-local-"+outcome, mode, "npm-old", npmOptions{proxy: proxy, block: block})
			add("LIFE-01", mode+"-"+outcome+"-cleanup", mode, "npm-old", npmOptions{proxy: proxy, block: block})
			add("NPM-01", mode+"-scoped-"+outcome, mode, "npm-old-scoped", npmOptions{proxy: proxy, block: block})
			for _, alias := range []string{"install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"} {
				add("NPM-01", mode+"-"+alias+"-"+outcome, mode, "npm-old", npmOptions{alias: alias, proxy: proxy, block: block})
			}
		}
	}
	for _, value := range []string{"", "0", "true", "1"} {
		name, mode := value, "resolution"
		if name == "" {
			name = "unset"
		}
		if value == "1" {
			mode = "proxy"
		}
		add("CORE-10", "proxy-env-"+name, mode, "npm-old", npmOptions{proxy: value, block: true})
	}
}

func prepareNPMProject(r *caseRun) (map[string][]byte, error) {
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	settings := map[string]string{
		"npm_config_cache":        filepath.Join(r.Root, "cache", "npm"),
		"npm_config_registry":     "https://registry.npmjs.org/",
		"npm_config_userconfig":   filepath.Join(r.Root, "home", ".npmrc"),
		"npm_config_globalconfig": filepath.Join(r.Root, "config", "npmrc"),
		"npm_config_audit":        "false", "npm_config_fund": "false", "npm_config_update_notifier": "false",
	}
	for key, value := range settings {
		r.Env[key] = value
	}
	r.Result.Observations["npm_environment"] = settings
	for _, key := range []string{"npm_config_userconfig", "npm_config_globalconfig"} {
		if err := os.WriteFile(r.Env[key], nil, 0600); err != nil {
			return nil, err
		}
	}
	manifest, err := os.ReadFile("testdata/npm_baseline/package.json")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(r.WorkDir, "package.json"), manifest, 0600); err != nil {
		return nil, err
	}
	if _, err := r.Command("lock-bootstrap", r.Cell.Executable, "install", "--package-lock-only", "--ignore-scripts"); err != nil {
		return nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	before := map[string][]byte{}
	for _, name := range []string{"package.json", "package-lock.json"} {
		before[name], err = os.ReadFile(filepath.Join(r.WorkDir, name))
		if err != nil {
			return nil, err
		}
		snapshot := filepath.Join(r.Root, "before-"+name)
		if err := os.WriteFile(snapshot, before[name], 0600); err != nil {
			return nil, err
		}
		if err := r.Keep("before-"+name, snapshot); err != nil {
			return nil, err
		}
	}
	if _, err := r.Command("git-init", r.Cell.Git, "init", "--quiet"); err != nil {
		return nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	if _, err := r.Command("git-origin", r.Cell.Git, "remote", "add", "origin", "https://example.invalid/scfw-e2e.git"); err != nil {
		return nil, err
	}
	return before, nil
}

func runNPMBaseline(r *caseRun, options npmOptions) error {
	c := r.Candidate
	before, err := prepareNPMProject(r)
	if err != nil {
		return err
	}
	delete(r.Env, "SCFW_PROXY_ENABLED")
	if options.proxy != "" {
		r.Env["SCFW_PROXY_ENABLED"] = options.proxy
	}
	if options.block {
		if err := writeFinding(r, "npm", c.Project, c.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	executable := r.Cell.Executable
	argv := []string{r.Binary, "run"}
	if options.errorOnBlock {
		argv = append(argv, "--error-on-block")
	}
	if options.explicit {
		directory := filepath.Join(r.Root, "manager path with spaces")
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		executable = filepath.Join(directory, "npm")
		if err := os.Symlink(r.Cell.Executable, executable); err != nil {
			return err
		}
		argv = append(argv, "--executable", executable)
	}
	alias := options.alias
	if alias == "" {
		alias = "install"
	}
	commandArgs := []string{"npm", alias, c.Project + "@" + c.Version, "--ignore-scripts", "--no-audit", "--no-fund"}
	argv = append(append(argv, "--"), commandArgs...)
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	nonzero := options.block && (options.errorOnBlock || options.proxy == "1")
	if command.ExitCode < 0 && command.Signal == "" {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("could not execute SCFW: %w", commandErr))
	}
	if command.ExitCode < 0 || (command.ExitCode > 0) != nonzero || command.Signal != "" {
		return fmt.Errorf("unexpected SCFW exit%d signal%q: %v", command.ExitCode, command.Signal, commandErr)
	}
	if options.proxy != "1" && nonzero && command.ExitCode != 1 {
		return fmt.Errorf("resolution error-on-block exit%d; want1", command.ExitCode)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (options.proxy == "1") || strings.Contains(string(stderr), "falling back to dry-run resolution") {
		return fmt.Errorf("incorrect npm inspection mode")
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	outcome := "ALLOW"
	if options.block {
		outcome = "BLOCK"
	}
	if err := assertPolicy(records, c, "npm", executable, outcome); err != nil {
		return err
	}
	if options.proxy != "1" && len(records) != 1 {
		return fmt.Errorf("resolution produced%d policy records; want1", len(records))
	}
	for _, record := range records {
		if record.Repository != "https://example.invalid/scfw-e2e.git" || record.Command != strings.Join(commandArgs, " ") {
			return fmt.Errorf("incorrect repository or command in npm policy record")
		}
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
	if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	for name, original := range before {
		after, err := os.ReadFile(filepath.Join(r.WorkDir, name))
		if err != nil {
			return err
		}
		if options.block && options.proxy != "1" && !bytes.Equal(original, after) {
			return fmt.Errorf("resolution BLOCK changed%s", name)
		}
		if err := r.Keep("after-"+name, filepath.Join(r.WorkDir, name)); err != nil {
			return err
		}
	}
	if err := assertNPMInstall(r, options.block); err != nil {
		return err
	}
	return assertCleanup(r, string(stderr))
}

func assertNPMInstall(r *caseRun, blocked bool) error {
	c := r.Candidate
	script, err := filepath.Abs("testdata/npm_baseline/inspect_install.cjs")
	if err != nil {
		return err
	}
	state, err := r.Command("installed-state", r.Cell.Runtime, script, r.WorkDir, c.Project, c.Module)
	if err != nil {
		return err
	}
	var installed struct {
		Present  bool   `json:"present"`
		Name     string `json:"name"`
		Version  string `json:"version"`
		Imported bool   `json:"imported"`
	}
	if err := readJSON(state.Stdout.Path, &installed); err != nil {
		return err
	}
	r.Result.Observations["installed"] = installed
	if installed.Present == blocked || (!blocked && (installed.Name != c.Project || installed.Version != c.Version || (c.Module != "" && !installed.Imported))) {
		return fmt.Errorf("unexpected npm installed state: %+v", installed)
	}
	if blocked {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := readJSON(filepath.Join(r.WorkDir, "package-lock.json"), &lock); err != nil {
		return err
	}
	entry := lock.Packages["node_modules/"+c.Project]
	if entry.Version != c.Version || entry.Resolved != c.Artifacts[0].URL || entry.Integrity != c.Artifacts[0].Integrity {
		return fmt.Errorf("npm installed an artifact different from registry discovery")
	}
	return r.Keep("installed-package", filepath.Join(r.WorkDir, "node_modules", filepath.FromSlash(c.Project), "package.json"))
}
