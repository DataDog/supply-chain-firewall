//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"
)

type pipOptions struct {
	block, errorOnBlock, explicit, spaces bool
	launcher, proxy                       string
}

func init() {
	add := func(id, variant, mode string, options pipOptions) {
		suites["pip-baseline"] = append(suites["pip-baseline"], scenario{Scenario: id, Variant: variant, Manager: "pip", Mode: mode, Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "pypi-old", Timeout: 3 * time.Minute, Run: func(r *caseRun) error { return runPipBaseline(r, options) }})
	}
	for _, mode := range []string{"resolution", "proxy"} {
		proxy := ""
		if mode == "proxy" {
			proxy = "1"
		}
		add("CORE-01", mode+"-allow", mode, pipOptions{proxy: proxy})
		add("CORE-02", mode+"-block-default", mode, pipOptions{proxy: proxy, block: true})
		add("CORE-02", mode+"-block-error", mode, pipOptions{proxy: proxy, block: true, errorOnBlock: true})
		add("CORE-12", mode+"-pip3", mode, pipOptions{proxy: proxy, launcher: "pip3"})
		add("CORE-12", mode+"-explicit-spaces", mode, pipOptions{proxy: proxy, explicit: true, spaces: true})
		add("REPORT-01", mode+"-local-allow", mode, pipOptions{proxy: proxy})
		add("REPORT-01", mode+"-local-block", mode, pipOptions{proxy: proxy, block: true, errorOnBlock: true})
	}
	for _, value := range []string{"", "0", "true", "1"} {
		name, mode := value, "resolution"
		if name == "" {
			name = "unset"
		}
		if value == "1" {
			mode = "proxy"
		}
		add("CORE-10", "proxy-env-"+name, mode, pipOptions{proxy: value})
	}
	for _, blocked := range []bool{false, true} {
		variant := "proxy-allowed-cleanup"
		if blocked {
			variant = "proxy-blocked-cleanup"
		}
		suites["pip-baseline"] = append(suites["pip-baseline"], scenario{Scenario: "LIFE-01", Variant: variant, Manager: "pip", Mode: "proxy", Backend: "local", RegistryProfile: "public-pypi", DiscoveryKey: "pypi-old", Timeout: 5 * time.Minute, Run: func(r *caseRun) error {
			if err := runPipBaseline(r, pipOptions{proxy: "1", block: blocked, errorOnBlock: blocked}); err != nil {
				return err
			}
			next := *r
			next.Root = filepath.Join(r.Root, "subsequent")
			next.WorkDir = filepath.Join(next.Root, "work")
			env, err := isolatedEnvironment(next.Root)
			if err != nil {
				return err
			}
			next.Env = env
			return runPipBaseline(&next, pipOptions{proxy: "1"})
		}})
	}
}
func runPipBaseline(r *caseRun, options pipOptions) error {
	c := r.Candidate
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	if options.proxy != "" {
		r.Env["SCFW_PROXY_ENABLED"] = options.proxy
	}
	venv := filepath.Join(r.Root, "venv")
	if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	python := filepath.Join(venv, "bin", "python")
	target := filepath.Join(r.Root, "installed packages")
	if options.block {
		if err := writeFinding(r, "PyPI", c.Project, c.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	if _, err := r.Command("git-init", r.Cell.Git, "init", "--quiet"); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", err)
	}
	if _, err := r.Command("git-origin", r.Cell.Git, "remote", "add", "origin", "https://example.invalid/scfw-e2e.git"); err != nil {
		return err
	}
	launcher := options.launcher
	if launcher == "" {
		launcher = "pip"
	}
	executable := r.Cell.Executable
	if launcher == "pip3" {
		executable = filepath.Join(filepath.Dir(executable), "pip3")
		if _, err := os.Stat(executable); err != nil {
			return classified("INFRASTRUCTURE_FAILURE", err)
		}
	}
	if options.spaces {
		dir := filepath.Join(r.Root, "manager path with spaces")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		link := filepath.Join(dir, launcher)
		if err := os.Symlink(executable, link); err != nil {
			return err
		}
		executable = link
	}
	report := filepath.Join(r.Root, "pip-install.json")
	argv := []string{r.Binary, "run"}
	if options.errorOnBlock {
		argv = append(argv, "--error-on-block")
	}
	if options.explicit {
		argv = append(argv, "--executable", executable)
	}
	argv = append(argv, "--", launcher, "install", "--no-deps", "--only-binary=:all:", "--ignore-installed", "--target", target, "--report", report, c.Project+"=="+c.Version)
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	expectedExit := 0
	if options.block && (options.errorOnBlock || options.proxy == "1") {
		expectedExit = 1
	}
	if command.ExitCode != expectedExit {
		return fmt.Errorf("SCFW exit=%d, want%d (error=%v)", command.ExitCode, expectedExit, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (options.proxy == "1") {
		return fmt.Errorf("SCFW selected the wrong inspection mode")
	}
	records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
	if err != nil {
		return err
	}
	outcome := "ALLOW"
	if options.block {
		outcome = "BLOCK"
	}
	if err := assertPolicy(records, c, launcher, executable, outcome); err != nil {
		return err
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
	if err := r.Keep("policy-"+filepath.Base(r.Root), r.Env["SCFW_LOG_FILE"]); err != nil {
		return err
	}
	for _, record := range records {
		if record.Repository != "https://example.invalid/scfw-e2e.git" || !strings.Contains(record.Command, c.Project+"=="+c.Version) {
			return fmt.Errorf("incorrect repository or command in policy report")
		}
	}
	script, err := filepath.Abs("testdata/pip_baseline/inspect_install.py")
	if err != nil {
		return err
	}
	state, err := r.Command("installed-state", python, "-I", script, target, c.Project, c.Module)
	if err != nil {
		return err
	}
	var installed struct {
		Present  bool   `json:"present"`
		Version  string `json:"version"`
		Imported bool   `json:"imported"`
	}
	if err := readJSON(state.Stdout.Path, &installed); err != nil {
		return err
	}
	r.Result.Observations["installed-"+filepath.Base(r.Root)] = installed
	if installed.Present == options.block || (!options.block && (installed.Version != c.Version || !installed.Imported)) {
		return fmt.Errorf("unexpected installed state: %+v", installed)
	}
	if !options.block {
		var reportData struct {
			Install []struct {
				DownloadInfo struct {
					URL         string `json:"url"`
					ArchiveInfo struct {
						Hashes map[string]string `json:"hashes"`
						Hash   string            `json:"hash"`
					} `json:"archive_info"`
				} `json:"download_info"`
			} `json:"install"`
		}
		if err := readJSON(report, &reportData); err != nil {
			return err
		}
		if len(reportData.Install) != 1 {
			return fmt.Errorf("expected one installed artifact")
		}
		archive := reportData.Install[0].DownloadInfo.ArchiveInfo
		hash := archive.Hashes["sha256"]
		if hash == "" {
			hash = strings.TrimPrefix(archive.Hash, "sha256=")
		}
		if reportData.Install[0].DownloadInfo.URL != c.Artifacts[0].URL || hash != c.Artifacts[0].SHA256 {
			return fmt.Errorf("pip installed an artifact different from registry discovery")
		}
		if err := r.Keep("install-"+filepath.Base(r.Root), report); err != nil {
			return err
		}
	}
	return assertCleanup(r, string(stderr))
}

type policyPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"package_name"`
	Version   string `json:"package_version"`
	Outcome   string `json:"outcome"`
	Findings  []struct {
		Verifier string `json:"verifier"`
		Severity string `json:"severity"`
		Text     string `json:"text"`
	} `json:"findings"`
	Failures []json.RawMessage `json:"failures"`
}
type policyRecord struct {
	Timestamp  time.Time       `json:"timestamp"`
	Command    string          `json:"command"`
	Manager    string          `json:"package_manager"`
	Executable string          `json:"executable"`
	Repository string          `json:"repository"`
	Outcome    string          `json:"outcome"`
	Packages   []policyPackage `json:"packages"`
}

func readPolicy(path string) ([]policyRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	var records []policyRecord
	for {
		var record policyRecord
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no local policy records")
	}
	return records, nil
}
func assertPolicy(records []policyRecord, c candidate, manager, executable, outcome string) error {
	found := false
	for _, record := range records {
		if record.Manager != manager || record.Executable != executable || record.Timestamp.IsZero() || record.Outcome != outcome {
			return fmt.Errorf("unexpected policy record manager/executable/action: %+v", record)
		}
		for _, pkg := range record.Packages {
			if strings.EqualFold(pkg.Ecosystem, c.Ecosystem) && strings.EqualFold(pkg.Name, c.Project) && pkg.Version == c.Version {
				found = true
				if pkg.Outcome != outcome {
					return fmt.Errorf("policy outcome=%s, want%s", pkg.Outcome, outcome)
				}
				if outcome == "BLOCK" {
					matched := false
					for _, finding := range pkg.Findings {
						if finding.Verifier == "FindingsListVerifier" && finding.Severity == "CRITICAL" && finding.Text == "SCFW E2E exact-version finding" {
							matched = true
						}
					}
					if !matched {
						return fmt.Errorf("BLOCK lacks exact-list finding")
					}
				}
			}
		}
	}
	if !found {
		return fmt.Errorf("missing exact package identity in policy report")
	}
	return nil
}
func writeFinding(r *caseRun, ecosystem, name, version, severity string) error {
	tmpl, err := template.ParseFiles("testdata/pip_baseline/finding.yaml.tmpl")
	if err != nil {
		return err
	}
	path := filepath.Join(r.Env["SCFW_HOME"], "list_verifier", "e2e.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return tmpl.Execute(file, map[string]string{"Ecosystem": ecosystem, "Name": name, "Version": version, "Severity": severity})
}
func assertCleanup(r *caseRun, stderr string) error {
	var remains []string
	err := filepath.WalkDir(r.Env["TMPDIR"], func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), "scfw-") {
			remains = append(remains, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(remains) > 0 {
		return fmt.Errorf("SCFW temporary material remains: %v", remains)
	}
	var listeners []string
	for _, match := range regexp.MustCompile(`started package manager proxy[^\n]*url=http://(127\.0\.0\.1:\d+)`).FindAllStringSubmatch(stderr, -1) {
		address := match[1]
		listeners = append(listeners, address)
		connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			connection.Close()
			return fmt.Errorf("proxy listener remains open at %s", address)
		}
	}
	if r.Spec.Mode == "proxy" && len(listeners) == 0 {
		return fmt.Errorf("proxy listener identity was not observed")
	}
	path := filepath.Join(r.Root, "cleanup.json")
	if err := writeJSON(path, map[string]any{"remaining_scfw_temp_paths": remains, "closed_listeners": listeners}); err != nil {
		return err
	}
	return r.Keep("cleanup-"+filepath.Base(r.Root), path)
}
