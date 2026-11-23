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
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var configAliasNames = []string{"bun", "bunx", "npm", "npx", "pip", "pip3", "pn", "pnpm", "pnpx", "pnx", "poetry", "uv", "uvx", "yarn"}
var configAllFlags = []string{"--alias-npm", "--alias-pip", "--alias-poetry", "--alias-uv", "--alias-yarn", "--alias-pnpm", "--alias-bun"}
var configRCNames = []string{".bashrc", ".bash_profile", ".zshrc", ".zprofile"}

const configBegin = "# BEGIN SCFW MANAGED BLOCK"
const configEnd = "# END SCFW MANAGED BLOCK"

func init() {
	add := func(id, name, shell, key string, run func(*caseRun) error) {
		capabilities := []string{"disposable-credentials"}
		if shell != "" {
			capabilities = append(capabilities, shell)
		}
		suites["configure-doctor"] = append(suites["configure-doctor"], scenario{Scenario: id, Variant: name, Manager: "npm", Mode: "resolution", Backend: "local", RegistryProfile: "public-npm", DiscoveryKey: key, Capabilities: capabilities, Timeout: 3 * time.Minute, Run: run})
	}
	for _, shell := range []string{"bash", "zsh"} {
		add("CFG-01", shell+"-alias-lifecycle", shell, "", func(r *caseRun) error { return runConfigLifecycle(r, shell) })
		add("CFG-02", shell+"-literal-exports", shell, "", func(r *caseRun) error { return runConfigQuoting(r, shell) })
		for _, blocked := range []bool{false, true} {
			outcome := "allow"
			if blocked {
				outcome = "block"
			}
			add("CFG-01", shell+"-install-"+outcome, shell, "npm-old", func(r *caseRun) error { return runConfigInstall(r, shell, blocked) })
		}
	}
	for _, variant := range []string{"malformed-block", "conflicting-flags", "missing-value", "unwritable-file"} {
		add("CFG-02", variant, "", "", func(r *caseRun) error { return runConfigFailure(r, variant) })
	}
	for _, variant := range []string{"unconfigured", "local-all", "datadog-environment", "datadog-missing", "wrong-target"} {
		add("CFG-04", variant, "", "", func(r *caseRun) error { return runConfigDoctor(r, variant) })
	}
}

// Every keychain-capable invocation gets a fresh private Linux bus with no
// activation directories. It cannot reach or activate the developer's secret
// service. Native macOS requires an explicitly provisioned disposable account;
// changing HOME alone never counts as keychain isolation.
func configCommand(r *caseRun, label string, args ...string) (commandEvidence, error) {
	argv := append([]string{r.Binary}, args...)
	switch runtime.GOOS {
	case "linux":
		launcher, err := exec.LookPath("dbus-run-session")
		if err != nil {
			return commandEvidence{}, classified("INFRASTRUCTURE_FAILURE", err)
		}
		conf, err := filepath.Abs("testdata/configure_doctor/dbus.conf")
		if err != nil {
			return commandEvidence{}, err
		}
		argv = append([]string{launcher, "--config-file=" + conf, "--"}, argv...)
		r.Result.Observations["credential_isolation"] = "fresh D-Bus session; no service activation directories"
	case "darwin":
		current, err := user.Current()
		if err != nil {
			return commandEvidence{}, err
		}
		if os.Getenv("SCFW_E2E_DISPOSABLE_USER") == "" || os.Getenv("SCFW_E2E_DISPOSABLE_USER") != current.Username {
			return commandEvidence{}, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("provision a disposable macOS account and set SCFW_E2E_DISPOSABLE_USER to its username"))
		}
		r.Result.Observations["credential_isolation"] = "operator-provisioned disposable macOS account: " + current.Username
	default:
		return commandEvidence{}, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("no credential isolation profile for %s", runtime.GOOS))
	}
	ev, err := r.Command(label, argv...)
	r.Result.SCFWExit, r.Result.SCFWSignal = ev.ExitCode, ev.Signal
	return ev, err
}
func configOutput(ev commandEvidence) (string, error) {
	out, err := os.ReadFile(ev.Stdout.Path)
	if err != nil {
		return "", err
	}
	stderr, err := os.ReadFile(ev.Stderr.Path)
	return string(out) + string(stderr), err
}
func configExpect(r *caseRun, label string, exit int, diagnostic string, args ...string) error {
	ev, runErr := configCommand(r, label, args...)
	if ev.ExitCode != exit || ev.TimedOut || ev.Signal != "" {
		return fmt.Errorf("%s exit=%d want=%d: %v", label, ev.ExitCode, exit, runErr)
	}
	out, err := configOutput(ev)
	if err != nil {
		return err
	}
	if !strings.Contains(out, diagnostic) {
		return fmt.Errorf("%s missing diagnostic %q: %s", label, diagnostic, out)
	}
	return nil
}
func configWriteRC(r *caseRun, names []string) ([]byte, error) {
	content, err := os.ReadFile("testdata/configure_doctor/startup.sh")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(r.Env["HOME"], name), content, 0600); err != nil {
			return nil, err
		}
	}
	return content, nil
}
func configReadRC(r *caseRun, name, label string) ([]byte, error) {
	path := filepath.Join(r.Env["HOME"], name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	snapshot := filepath.Join(r.Root, label+"-"+strings.TrimPrefix(name, "."))
	if err := os.WriteFile(snapshot, data, 0600); err != nil {
		return nil, err
	}
	return data, r.Keep(label+"-"+name, snapshot)
}
func runConfigLifecycle(r *caseRun, shell string) error {
	// Only two startup files exist; configure must not invent the others.
	names := []string{".bashrc", ".zshrc"}
	original, err := configWriteRC(r, names)
	if err != nil {
		return err
	}
	if err := configExpect(r, "initial", 0, "Configuration updated", "configure", "--alias-npm"); err != nil {
		return err
	}
	first, err := configReadRC(r, names[0], "initial")
	if err != nil {
		return err
	}
	if err := configExpect(r, "repeat", 0, "Configuration updated", "configure", "--alias-npm"); err != nil {
		return err
	}
	repeated, err := configReadRC(r, names[0], "repeated")
	if err != nil {
		return err
	}
	if !bytes.Equal(first, repeated) {
		return fmt.Errorf("repeated configure changed startup bytes")
	}
	if err := configExpect(r, "additive", 0, "Configuration updated", "configure", "--alias-pip", "--alias-poetry", "--alias-uv"); err != nil {
		return err
	}
	for _, name := range names {
		data, err := configReadRC(r, name, "additive")
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(data, original) || strings.Count(string(data), configBegin) != 1 || strings.Count(string(data), configEnd) != 1 {
			return fmt.Errorf("startup content/block changed unexpectedly")
		}
		for _, alias := range []string{"npm", "npx", "pip", "pip3", "poetry", "uv", "uvx"} {
			if !bytes.Contains(data, []byte(`alias `+alias+`="scfw run -- `+alias+`"`)) {
				return fmt.Errorf("missing additive alias %s", alias)
			}
		}
	}
	if err := configExpect(r, "selective-remove", 0, "Configuration updated", "configure", "--remove-alias-pip"); err != nil {
		return err
	}
	for _, name := range names {
		data, err := configReadRC(r, name, "selective")
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("alias pip")) || !bytes.Contains(data, []byte("alias npm=")) {
			return fmt.Errorf("selective removal changed unrelated aliases")
		}
	}
	script, err := filepath.Abs("testdata/configure_doctor/inspect_aliases.sh")
	if err != nil {
		return err
	}
	executable, err := exec.LookPath(shell)
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	if _, err := r.Command("inspect-selective-aliases", executable, script, filepath.Join(r.Env["HOME"], "."+shell+"rc")); err != nil {
		return err
	}
	exit, diagnostic := 0, "Configuration updated"
	if runtime.GOOS == "linux" {
		exit, diagnostic = 1, "failed to remove Datadog"
	}
	if err := configExpect(r, "remove-all", exit, diagnostic, "configure", "--remove"); err != nil {
		return err
	}
	for _, name := range names {
		data, err := configReadRC(r, name, "removed")
		if err != nil {
			return err
		}
		if !bytes.Equal(data, original) {
			return fmt.Errorf("remove did not preserve unmanaged bytes in %s", name)
		}
	}
	for _, name := range []string{".bash_profile", ".zprofile"} {
		if _, err := os.Stat(filepath.Join(r.Env["HOME"], name)); !os.IsNotExist(err) {
			return fmt.Errorf("missing startup file %s was fabricated", name)
		}
	}
	r.Result.PolicyOutcome = "NOT_OBSERVED"
	r.Result.ResolvedAction = "CONFIGURED"
	return nil
}
func runConfigQuoting(r *caseRun, shell string) error {
	if _, err := configWriteRC(r, []string{".bashrc"}); err != nil {
		return err
	}
	home := filepath.Join(r.Root, `space ' quote " $HOME $(printf expanded) backtick`+"`")
	site := `space ' quote " $HOME $(printf expanded)`
	if err := configExpect(r, "configure-exports", 0, "Configuration updated", "configure", "--scfw-home", home, "--dd-site", site); err != nil {
		return err
	}
	// Re-read and rewrite exports through the additive path as well.
	if err := configExpect(r, "preserve-exports", 0, "Configuration updated", "configure", "--alias-npm"); err != nil {
		return err
	}
	script, err := filepath.Abs("testdata/configure_doctor/exports.sh")
	if err != nil {
		return err
	}
	executable, err := exec.LookPath(shell)
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	ev, err := r.Command("source-exports", executable, script, filepath.Join(r.Env["HOME"], ".bashrc"))
	if err != nil {
		return err
	}
	actual, err := os.ReadFile(ev.Stdout.Path)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, []byte(home+"\x00"+site+"\x00")) {
		return fmt.Errorf("sourced exports differ from literal configured values: %q", actual)
	}
	_, err = configReadRC(r, ".bashrc", "quoted")
	return err
}
func runConfigFailure(r *caseRun, variant string) error {
	original, err := configWriteRC(r, configRCNames)
	if err != nil {
		return err
	}
	path := filepath.Join(r.Env["HOME"], ".bashrc")
	args := []string{"configure", "--alias-npm"}
	diagnostic := ""
	partial := false
	switch variant {
	case "malformed-block":
		original = append(original, []byte(configBegin+"\nalias npm=broken\n")...)
		if err := os.WriteFile(path, original, 0600); err != nil {
			return err
		}
		diagnostic = "missing end marker"
		partial = true
	case "conflicting-flags":
		args = append(args, "--remove-alias-npm")
		diagnostic = "none of the others can be"
	case "missing-value":
		args = []string{"configure", "--scfw-home"}
		diagnostic = "flag needs an argument"
	case "unwritable-file":
		if os.Geteuid() == 0 {
			return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("permission scenario requires an unprivileged runner"))
		}
		if err := os.Chmod(path, 0400); err != nil {
			return err
		}
		defer func() { _ = os.Chmod(path, 0600) }()
		diagnostic = "permission denied"
		partial = true
	}
	if err := configExpect(r, variant, 1, diagnostic, args...); err != nil {
		return err
	}
	for _, name := range configRCNames {
		data, err := configReadRC(r, name, "after-error")
		if err != nil {
			return err
		}
		if name == ".bashrc" {
			if !bytes.Equal(data, original) {
				return fmt.Errorf("failed startup file was modified")
			}
			continue
		}
		if partial != bytes.Contains(data, []byte("alias npm=")) {
			return fmt.Errorf("unexpected partial write to %s", name)
		}
	}
	return nil
}
func runConfigDoctor(r *caseRun, variant string) error {
	if _, err := configWriteRC(r, configRCNames); err != nil {
		return err
	}
	if variant != "unconfigured" {
		if err := configExpect(r, "configure-all", 0, "Configuration updated", append([]string{"configure"}, configAllFlags...)...); err != nil {
			return err
		}
	}
	wantExit := 0
	switch variant {
	case "unconfigured":
		wantExit = 1
	case "datadog-environment":
		r.Env["SCFW_MODE"] = "datadog"
		r.Env["DD_API_KEY"] = "synthetic-doctor-api-value"
		r.Env["DD_APP_KEY"] = "synthetic-doctor-app-value"
	case "datadog-missing":
		r.Env["SCFW_MODE"] = "datadog"
		wantExit = 1
	case "wrong-target":
		path := filepath.Join(r.Env["HOME"], ".bashrc")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data = bytes.Replace(data, []byte(`alias npm="scfw run -- npm"`), []byte(`alias npm="echo bypass"`), 1)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		wantExit = 1
	}
	ev, runErr := configCommand(r, "doctor", "doctor")
	if ev.ExitCode != wantExit || ev.TimedOut || ev.Signal != "" {
		return fmt.Errorf("doctor exit=%d want=%d: %v", ev.ExitCode, wantExit, runErr)
	}
	out, err := configOutput(ev)
	if err != nil {
		return err
	}
	for _, secret := range []string{"synthetic-doctor-api-value", "synthetic-doctor-app-value"} {
		if strings.Contains(out, secret) {
			return fmt.Errorf("doctor exposed a credential value")
		}
	}
	for _, name := range configAliasNames {
		text := "Alias " + name + " is set"
		if variant == "unconfigured" {
			text = "Alias " + name + " is not set"
		}
		if !strings.Contains(out, text) {
			return fmt.Errorf("doctor omitted %q", text)
		}
	}
	expected := "Evaluation mode: " + r.Env["SCFW_MODE"]
	if !strings.Contains(out, expected) {
		return fmt.Errorf("doctor omitted %q", expected)
	}
	if variant == "datadog-environment" && strings.Count(out, "found in Environment") != 2 {
		return fmt.Errorf("doctor omitted environment credential sources")
	}
	if variant == "datadog-missing" && (!strings.Contains(out, "API Key not found") || !strings.Contains(out, "Application Key not found")) {
		return fmt.Errorf("doctor omitted missing credentials")
	}
	if r.Env["SCFW_MODE"] == "local" && strings.Count(out, "not required in local evaluation mode") != 2 {
		return fmt.Errorf("local doctor required credentials")
	}
	if variant == "wrong-target" && !strings.Contains(out, `targets "echo bypass"`) {
		return fmt.Errorf("doctor accepted a bypass alias")
	}
	r.Result.PolicyOutcome = "NOT_OBSERVED"
	r.Result.ResolvedAction = "DIAGNOSED"
	return nil
}
func runConfigInstall(r *caseRun, shell string, blocked bool) error {
	if _, err := prepareNPMProject(r); err != nil {
		return err
	}
	if _, err := configWriteRC(r, configRCNames); err != nil {
		return err
	}
	if err := configExpect(r, "configure-alias", 0, "Configuration updated", "configure", "--alias-npm"); err != nil {
		return err
	}
	bin := filepath.Join(r.Root, "shell-bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		return err
	}
	if err := os.Symlink(r.Binary, filepath.Join(bin, "scfw")); err != nil {
		return err
	}
	r.Env["PATH"] = bin + string(os.PathListSeparator) + r.Env["PATH"]
	r.Env["SCFW_E2E_PACKAGE"] = r.Candidate.Project + "@" + r.Candidate.Version
	if blocked {
		if err := writeFinding(r, "npm", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	script, err := filepath.Abs("testdata/configure_doctor/invoke." + shell)
	if err != nil {
		return err
	}
	executable, err := exec.LookPath(shell)
	if err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	ev, err := r.Command("alias-install", executable, script)
	if err != nil {
		return err
	}
	r.Result.SCFWExit, r.Result.SCFWSignal = ev.ExitCode, ev.Signal
	out, err := os.ReadFile(ev.Stdout.Path)
	if err != nil {
		return err
	}
	if !bytes.Contains(out, []byte("scfw run -- npm")) {
		return fmt.Errorf("shell did not expose the configured npm alias")
	}
	outcome := "ALLOW"
	if blocked {
		outcome = "BLOCK"
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	if err := assertPolicy(records, r.Candidate, "npm", r.Cell.Executable, outcome); err != nil {
		return err
	}
	if err := assertNPMInstall(r, blocked); err != nil {
		return err
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
	return nil
}
