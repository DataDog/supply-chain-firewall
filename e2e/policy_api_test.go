//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func init() {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		modes := []string{"resolution", "proxy"}
		if manager == "uv" {
			modes = []string{"proxy"}
		}
		for _, mode := range modes {
			for _, outcome := range []string{"ALLOW", "BLOCK"} {
				key, registry := "pypi-old", "public-pypi"
				if manager == "npm" {
					key, registry = "npm-old", "public-npm"
				}
				suites["policy-api"] = append(suites["policy-api"], scenario{Scenario: "REPORT-01", Variant: manager + "-" + mode + "-" + strings.ToLower(outcome), Manager: manager, Mode: mode, Backend: "datadog", RegistryProfile: registry, DiscoveryKey: key, Timeout: 5 * time.Minute, Run: func(r *caseRun) error { return runPolicyAPI(r, outcome) }})
			}
		}
	}
}

func preparePolicyCommand(r *caseRun) (string, []string, error) {
	var python string
	var args []string
	c := r.Candidate
	switch r.Cell.Manager {
	case "npm":
		if _, err := prepareNPMProject(r); err != nil {
			return "", nil, err
		}
		args = []string{"npm", "install", c.Project + "@" + c.Version, "--ignore-scripts", "--no-audit", "--no-fund"}
	case "poetry":
		var err error
		python, err = preparePoetry(r, "install")
		if err != nil {
			return "", nil, err
		}
		args = []string{"poetry", "--no-interaction", "install"}
	case "pip", "uv":
		if r.Cell.Manager == "uv" {
			if _, _, err := prepareUV(r, uvOptions{flag: "1"}); err != nil {
				return "", nil, err
			}
		}
		venv := filepath.Join(r.Root, "venv")
		if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
			return "", nil, classified("INFRASTRUCTURE_FAILURE", err)
		}
		python = filepath.Join(venv, "bin", "python")
		if r.Cell.Manager == "uv" {
			args = []string{"uv", "--verbose", "pip", "install", "--python", python, c.Project + "==" + c.Version}
		} else {
			parts := strings.Split(r.Cell.RuntimeVersion, ".")
			if len(parts) < 2 {
				return "", nil, fmt.Errorf("invalid Python pin")
			}
			target := filepath.Join(venv, "lib", "python"+strings.Join(parts[:2], "."), "site-packages")
			args = []string{"pip", "install", "--no-deps", "--only-binary=:all:", "--ignore-installed", "--target", target, "--report", filepath.Join(r.Root, "pip-install.json"), c.Project + "==" + c.Version}
		}
		for _, argv := range [][]string{{r.Cell.Git, "init", "--quiet"}, {r.Cell.Git, "remote", "add", "origin", "https://example.invalid/scfw-e2e.git"}} {
			if _, err := r.Command("git-bootstrap", argv...); err != nil {
				return "", nil, err
			}
		}
	default:
		return "", nil, fmt.Errorf("unknown policy manager %s", r.Cell.Manager)
	}
	if _, err := r.Command("credentialed-repository", r.Cell.Git, "remote", "set-url", "origin", "https://fixture-user:fixture-password@example.invalid/scfw-e2e.git"); err != nil {
		return "", nil, err
	}
	delete(r.Env, "SCFW_PROXY_ENABLED")
	if r.Spec.Mode == "proxy" {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
	}
	return python, args, nil
}

func assertPolicyInstall(r *caseRun, python string, blocked bool) error {
	if r.Cell.Manager == "npm" {
		return assertNPMInstall(r, blocked)
	}
	version := r.Candidate.Version
	if blocked {
		version = ""
	}
	if err := assertUVInstalled(r, python, version, "installed"); err != nil {
		return err
	}
	if blocked {
		return nil
	}
	switch r.Cell.Manager {
	case "pip":
		path := filepath.Join(r.Root, "pip-install.json")
		var report pipGraphReport
		if err := readJSON(path, &report); err != nil {
			return err
		}
		if err := matchPipInputReport(report, []candidate{r.Candidate}); err != nil {
			return err
		}
		return r.Keep("installed-artifact-"+filepath.Base(r.Root), path)
	case "poetry":
		file, err := poetryDownloadedArchive(r.Env["POETRY_CACHE_DIR"], r.Candidate)
		if err != nil {
			return err
		}
		r.Result.Evidence["installed-wheel-"+filepath.Base(r.Root)] = file
	}
	return nil
}

func runPolicyAPI(r *caseRun, outcome string) (err error) {
	fixture, err := startPolicyFixture(r, outcome)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fixture.closeAndKeep(r)) }()
	// The independent native install proves registry/runtime eligibility before
	// assigning any SCFW failure to the implementation under test.
	native := *r
	native.Root = filepath.Join(r.Root, "native-control")
	native.WorkDir = filepath.Join(native.Root, "work")
	native.Env, err = isolatedEnvironment(native.Root)
	if err != nil {
		return err
	}
	native.Env["PATH"] = r.Env["PATH"]
	python, args, err := preparePolicyCommand(&native)
	if err != nil {
		return err
	}
	if _, err := native.Command("native-install", append([]string{r.Cell.Executable}, args[1:]...)...); err != nil {
		return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("native public install: %w", err))
	}
	if err := assertPolicyInstall(&native, python, false); err != nil {
		return err
	}
	r.Result.Observations["native_control_installed"] = r.Candidate.Version
	python, args, err = preparePolicyCommand(r)
	if err != nil {
		return err
	}
	argv := append([]string{r.Binary, "run", "--error-on-block", "--executable", r.Cell.Executable, "--"}, args...)
	command, commandErr := r.Command("scfw", argv...)
	if command.TimedOut {
		return commandErr
	}
	blocked := outcome == "BLOCK"
	wantExit := 0
	if blocked {
		wantExit = 1
		if r.Cell.Manager == "uv" {
			wantExit = 2
		}
	}
	if command.ExitCode != wantExit || command.Signal != "" {
		return fmt.Errorf("SCFW exit %d signal %q, want %d: %v", command.ExitCode, command.Signal, wantExit, commandErr)
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	if strings.Contains(string(stderr), "running command through proxy") != (r.Spec.Mode == "proxy") || strings.Contains(string(stderr), "falling back to dry-run resolution") {
		return fmt.Errorf("incorrect policy API inspection mode")
	}
	fixture.mutex.Lock()
	events := append([]policyAPIExchange(nil), fixture.exchanges...)
	fixture.mutex.Unlock()
	if err := assertPolicyAPIExchanges(events, r, args, command, outcome); err != nil {
		return err
	}
	r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
	if err := assertPolicyInstall(r, python, blocked); err != nil {
		return err
	}
	if r.Cell.Manager == "uv" && !blocked && !strings.Contains(string(stderr), r.Candidate.Artifacts[0].Name) {
		return fmt.Errorf("uv did not identify the selected public wheel")
	}
	if err := assertUVNoPolicy(r); err != nil {
		return err
	}
	return assertCleanup(r, string(stderr))
}

type policyAPIEnvelope struct {
	Data struct {
		Type       string          `json:"type"`
		ID         string          `json:"id"`
		Attributes json.RawMessage `json:"attributes"`
	} `json:"data"`
}

type policyAPIPackage struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"package_name"`
	Version   string    `json:"package_version"`
	Source    string    `json:"package_source"`
	Published time.Time `json:"publish_date"`
}

func assertPolicyAPIExchanges(events []policyAPIExchange, r *caseRun, args []string, command commandEvidence, outcome string) error {
	if len(events) != 2 || events[0].Path != policyEvaluatePath || events[1].Path != policyReportPath {
		return fmt.Errorf("expected one evaluate then report for exact package identity, got %+v", events)
	}
	var requests [2]policyAPIEnvelope
	for i, event := range events {
		if event.Error != "" || !event.Authenticated || !event.TLS || event.Method != http.MethodPost || event.Host != "api.scfw.test" || event.ContentType != "application/json" {
			return fmt.Errorf("incorrect API transport: %+v", event)
		}
		if err := json.Unmarshal(event.Request, &requests[i]); err != nil {
			return err
		}
		kind := "scfw-policy-evaluate-request"
		if i == 1 {
			kind = "scfw-report-request"
		}
		if requests[i].Data.Type != kind || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(requests[i].Data.ID) {
			return fmt.Errorf("incorrect API request type or UUID")
		}
	}
	if requests[0].Data.ID == requests[1].Data.ID {
		return fmt.Errorf("evaluation and report reused request IDs")
	}
	var evaluate struct {
		Packages    []policyAPIPackage `json:"packages"`
		Interactive *bool              `json:"is_interactive"`
	}
	if err := json.Unmarshal(requests[0].Data.Attributes, &evaluate); err != nil {
		return err
	}
	if len(evaluate.Packages) != 1 || evaluate.Interactive == nil || *evaluate.Interactive {
		return fmt.Errorf("incorrect package count or noninteractive evaluation flag")
	}
	source := r.Candidate.Artifacts[0].URL
	published := r.Candidate.Artifacts[0].UploadedAt
	if r.Cell.Manager == "poetry" && r.Spec.Mode == "resolution" {
		source = "https://pypi.org/project/" + r.Candidate.Project + "/" + r.Candidate.Version + "/"
		var metadata pypiMetadata
		if len(r.Candidate.Metadata) == 0 {
			return fmt.Errorf("missing Poetry release publication evidence")
		}
		if err := readJSON(r.Candidate.Metadata[0].Body.Path, &metadata); err != nil {
			return err
		}
		for _, file := range metadata.Releases[r.Candidate.Version] {
			if file.UploadTime.After(published) {
				published = file.UploadTime
			}
		}
	}
	pkg := evaluate.Packages[0]
	if !strings.EqualFold(pkg.Ecosystem, r.Candidate.Ecosystem) || pkg.Name != r.Candidate.Project || pkg.Version != r.Candidate.Version || pkg.Source != source || published.IsZero() || !pkg.Published.Equal(published) || pkg.Published.After(command.StartedAt) {
		return fmt.Errorf("incorrect evaluated package identity/source/publication: %+v", pkg)
	}
	var report struct {
		Cwd        string    `json:"cwd"`
		Executable string    `json:"executable"`
		Hostname   string    `json:"hostname"`
		Timestamp  time.Time `json:"install_timestamp"`
		Manager    string    `json:"package_manager"`
		Command    string    `json:"command"`
		Repository string    `json:"repository"`
		Outcome    string    `json:"outcome"`
		Reports    []struct {
			Ecosystem string            `json:"ecosystem"`
			Package   string            `json:"package"`
			Version   string            `json:"version"`
			Source    string            `json:"package_artifact_source"`
			Warning   bool              `json:"warning"`
			Failures  []json.RawMessage `json:"failures"`
			Policies  []struct {
				Type    string `json:"type"`
				Rule    string `json:"rule"`
				Outcome string `json:"outcome"`
			} `json:"matched_policies"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(requests[1].Data.Attributes, &report); err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if report.Cwd != r.WorkDir || report.Executable != r.Cell.Executable || report.Hostname != hostname || report.Timestamp.Before(command.StartedAt.Truncate(time.Second)) || report.Timestamp.After(command.EndedAt) || report.Manager != r.Cell.Manager || report.Command != strings.Join(args, " ") || report.Repository != "https://example.invalid/scfw-e2e.git" || report.Outcome != outcome || len(report.Reports) != 1 {
		return fmt.Errorf("incorrect command-level report metadata: %+v", report)
	}
	recorded := report.Reports[0]
	if recorded.Ecosystem != pkg.Ecosystem || recorded.Package != pkg.Name || recorded.Version != pkg.Version || recorded.Source != source || recorded.Warning || len(recorded.Failures) != 0 || len(recorded.Policies) != 1 {
		return fmt.Errorf("incorrect reported package decision: %+v", recorded)
	}
	policy := recorded.Policies[0]
	if policy.Type != "org" || policy.Rule != "e2e-exact-version" || policy.Outcome != outcome {
		return fmt.Errorf("report lost the fixture policy identity: %+v", policy)
	}
	return nil
}

func TestHarnessPolicyAPIAssertions(t *testing.T) {
	var fixtures map[string][]policyAPIExchange
	if err := readJSON("testdata/policy_api/requests.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	command := commandEvidence{StartedAt: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), EndedAt: time.Date(2026, 1, 10, 0, 0, 2, 0, time.UTC)}
	r := &caseRun{WorkDir: "/work", Cell: cell{Manager: "pip", Executable: "/pip"}, Candidate: candidate{Ecosystem: "pypi", Project: "idna", Version: "1.0", Artifacts: []artifact{{URL: "https://files.pythonhosted.org/idna.whl", UploadedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	for name, events := range fixtures {
		for i := range events {
			events[i].Request = bytesReplaceHostname(events[i].Request, hostname)
		}
		err := assertPolicyAPIExchanges(events, r, []string{"pip", "install", "idna==1.0"}, command, "BLOCK")
		if (err == nil) != (name == "valid") {
			t.Errorf("%s accepted=%v: %v", name, err == nil, err)
		}
	}
}

func bytesReplaceHostname(data []byte, hostname string) []byte {
	escaped, _ := json.Marshal(hostname)
	return []byte(strings.ReplaceAll(string(data), `"FIXTURE_HOSTNAME"`, string(escaped)))
}
