//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"text/template"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type uvConfigCase struct {
	name                                    string
	script, block, merged, reject, metadata bool
}

func init() {
	add := func(id string, options uvConfigCase) {
		variant := options.name
		key, profile := "pypi-old", "public-pypi"
		if options.reject {
			key, profile = "", "none"
		} else if options.block {
			variant += "-block"
		} else {
			variant += "-allow"
		}
		capabilities := []string{}
		if strings.HasPrefix(options.name, "working-directory-") {
			capabilities = append(capabilities, "uv-working-directory-env")
		}
		if options.merged {
			capabilities = append(capabilities, "uv-file-proxy")
		}
		suites["uv-config-scripts"] = append(suites["uv-config-scripts"], scenario{
			Scenario: id, Variant: variant, Manager: "uv", Mode: "proxy", Backend: "local",
			RegistryProfile: profile, DiscoveryKey: key, Capabilities: capabilities, Timeout: 3 * time.Minute,
			Run: func(r *caseRun) error { return runUVConfigScript(r, options) },
		})
	}
	for _, name := range []string{"local-script", "symlink-script"} {
		for _, block := range []bool{false, true} {
			add("UV-06", uvConfigCase{name: name, script: true, block: block})
		}
	}
	add("UV-06", uvConfigCase{name: "registry-metadata-only", script: true, block: true, metadata: true})
	for _, name := range []string{"inline-http", "inline-https", "inline-no-config", "inline-explicit-config", "remote-script", "stdin-script", "oversized-script", "malformed-script"} {
		add("UV-06", uvConfigCase{name: name, script: true, reject: true})
	}
	for _, name := range []string{"uv-toml", "pyproject", "user-project", "uv-over-pyproject", "explicit-config", "environment-config", "environment-index", "cli-index", "no-config-cli", "no-config-env", "relative-directory", "symlink-parent", "working-directory-env", "working-directory-legacy-env", "workspace", "workspace-exclusion"} {
		for _, block := range []bool{false, true} {
			add("UV-07", uvConfigCase{name: name, block: block})
		}
	}
	for _, name := range []string{"merged-project", "merged-explicit", "merged-symlink", "merged-workspace"} {
		for _, block := range []bool{false, true} {
			add("UV-07", uvConfigCase{name: name, block: block, merged: true})
		}
	}
}

type uvConfigState struct {
	Argv   []string          `json:"argv"`
	Exit   int               `json:"exit"`
	Offset int64             `json:"stdin_offset"`
	Size   int64             `json:"stdin_size"`
	Merged map[string]string `json:"merged_configs"`
}

func uvFixture(name string, data map[string]string) ([]byte, error) {
	raw, err := os.ReadFile("testdata/uv_config_scripts/configurations.toml.tmpl")
	if err != nil {
		return nil, err
	}
	var cases map[string]map[string]any
	if err = toml.Unmarshal(raw, &cases); err != nil {
		return nil, err
	}
	selected, ok := cases[name]
	if !ok {
		return nil, fmt.Errorf("unknown uv fixture %s", name)
	}
	raw, err = toml.Marshal(selected)
	if err != nil {
		return nil, err
	}
	return uvRender(string(raw), data)
}
func uvRender(raw string, data map[string]string) ([]byte, error) {
	tmpl, err := template.New("uv").Option("missingkey=error").Parse(raw)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	err = tmpl.Execute(&output, data)
	return output.Bytes(), err
}
func uvWriteSnapshot(path string, content []byte, original map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		return err
	}
	original[path] = bytes.Clone(content)
	return nil
}

func runUVConfigScript(r *caseRun, options uvConfigCase) error {
	launcher, executable, err := prepareUV(r, uvOptions{flag: "1"})
	if err != nil {
		return err
	}
	delete(r.Env, "UV_DEFAULT_INDEX")
	delete(r.Env, "UV_NO_CONFIG")
	r.Env["UV_NO_SYSTEM_CONFIG"] = "1"
	original := map[string][]byte{}
	var args []string
	var lock string
	var remoteHits atomic.Int32
	if options.script {
		args, lock, err = prepareUVScript(r, options, original, &remoteHits)
	} else {
		args, err = prepareUVConfiguration(r, options, original)
	}
	if err != nil {
		return err
	}
	selectedEnvironment := map[string]string{}
	for _, key := range []string{"UV_INDEX_URL", "UV_CONFIG_FILE", "UV_NO_CONFIG", "UV_NO_SYSTEM_CONFIG", "UV_WORKING_DIR", "UV_WORKING_DIRECTORY"} {
		if value, ok := r.Env[key]; ok {
			selectedEnvironment[key] = value
		}
	}
	r.Result.Observations["uv_environment"] = selectedEnvironment
	for path := range original {
		if err := r.Keep("before-"+filepath.ToSlash(strings.TrimPrefix(path, r.Root+string(os.PathSeparator))), path); err != nil {
			return err
		}
	}
	if options.block {
		if err := writeFinding(r, "PyPI", r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
			return err
		}
	}
	input := filepath.Join(r.Root, "stdin.txt")
	if err := os.WriteFile(input, []byte("SCFW must leave rejected script stdin unread\n"), 0600); err != nil {
		return err
	}
	if err := r.Keep("stdin-before", input); err != nil {
		return err
	}
	statePath := filepath.Join(r.Root, "observed.json")
	observer, err := filepath.Abs("testdata/uv_config_scripts/observe.py")
	if err != nil {
		return err
	}
	argv := uvFirewallArgs(r, launcher, executable, uvOptions{}, args)
	command, commandErr := r.Command("scfw-observed", append([]string{r.Cell.Runtime, observer, input, statePath, r.Env["TMPDIR"]}, argv...)...)
	if command.TimedOut {
		return commandErr
	}
	var state uvConfigState
	if err := readJSON(statePath, &state); err != nil {
		return err
	}
	if err := recordUVObservation(r, state, statePath, argv, command); err != nil {
		return err
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	for path, want := range original {
		actual, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, want) {
			return fmt.Errorf("source configuration/script changed: %s", path)
		}
		if err := r.Keep("after-"+filepath.ToSlash(strings.TrimPrefix(path, r.Root+string(os.PathSeparator))), path); err != nil {
			return err
		}
	}
	if err := r.Keep("stdin-after", input); err != nil {
		return err
	}
	if r.Result.Evidence["stdin-before"].SHA256 != r.Result.Evidence["stdin-after"].SHA256 {
		return fmt.Errorf("stdin bytes changed")
	}
	if _, err := os.Stat(filepath.Join(r.WorkDir, "script-executed")); !os.IsNotExist(err) {
		return fmt.Errorf("script body unexpectedly executed: %v", err)
	}
	if options.reject {
		expected := "could not inspect uv script metadata"
		if strings.HasPrefix(options.name, "inline-") {
			expected = "does not support inline script proxy settings"
		}
		if state.Exit == 0 || !strings.Contains(string(stderr), expected) {
			return fmt.Errorf("script rejection missing: exit=%d: %s", state.Exit, stderr)
		}
		if state.Offset != 0 || state.Size == 0 {
			return fmt.Errorf("rejection consumed stdin: %+v", state)
		}
		if remoteHits.Load() != 0 {
			return fmt.Errorf("rejected remote script was fetched")
		}
		r.Result.Observations["remote_script_requests"] = remoteHits.Load()
		if err := assertUVNoPolicy(r); err != nil {
			return err
		}
		r.Result.ResolvedAction = "REJECTED"
		if lock != "" {
			if _, err := os.Stat(lock); !os.IsNotExist(err) {
				return fmt.Errorf("rejected invocation created lockfile")
			}
		}
		return assertUVNoProxy(r, string(stderr))
	}
	if options.metadata {
		if state.Exit != 0 {
			return fmt.Errorf("metadata-only lock failed: %v", commandErr)
		}
		if err := assertUVNoPolicy(r); err != nil {
			return err
		}
		r.Result.ResolvedAction = "METADATA_ONLY"
	} else {
		if (state.Exit != 0) != options.block {
			return fmt.Errorf("unexpected uv exit %d (block=%v): %v", state.Exit, options.block, commandErr)
		}
		records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
		if err != nil {
			return err
		}
		outcome := "ALLOW"
		if options.block {
			outcome = "BLOCK"
		}
		if err := assertPolicy(records, r.Candidate, launcher, executable, outcome); err != nil {
			return err
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
		if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
			return err
		}
	}
	if options.script {
		content, readErr := os.ReadFile(lock)
		if options.block && !options.metadata {
			if !os.IsNotExist(readErr) {
				return fmt.Errorf("blocked download wrote a lockfile")
			}
		} else {
			if readErr != nil {
				return readErr
			}
			if !bytes.Contains(content, []byte("name = "+strconv.Quote(r.Candidate.Project))) || !bytes.Contains(content, []byte("version = "+strconv.Quote(r.Candidate.Version))) {
				return fmt.Errorf("lockfile omitted selected identity")
			}
			if !options.metadata && !bytes.Contains(content, []byte(r.Candidate.Artifacts[0].URL)) {
				return fmt.Errorf("lockfile omitted discovered artifact")
			}
			if err := r.Keep("script-lock", lock); err != nil {
				return err
			}
		}
	} else {
		expected := r.Candidate.Version
		if options.block {
			expected = ""
		}
		if err := assertUVInstalled(r, filepath.Join(r.Root, "venv", "bin", "python"), expected, "configured"); err != nil {
			return err
		}
	}
	if options.merged {
		if len(state.Merged) == 0 {
			return fmt.Errorf("invocation merged uv.toml was not observed")
		}
		for path, content := range state.Merged {
			var config map[string]any
			if err := toml.Unmarshal([]byte(content), &config); err != nil {
				return err
			}
			proxy, ok := config["https-proxy"].(string)
			if !ok || !strings.HasPrefix(proxy, "http://127.0.0.1:") || proxy == "http://127.0.0.1:9" || config["http-proxy"] != proxy {
				return fmt.Errorf("merged config did not use invocation proxy")
			}
			bypass, ok := config["no-proxy"].([]any)
			if !ok || len(bypass) != 0 || config["index-url"] != "https://pypi.org/simple" {
				return fmt.Errorf("merged config changed nonrouting settings or retained proxy bypass")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				return fmt.Errorf("temporary merged config remains")
			}
		}
	}
	return assertCleanup(r, string(stderr))
}

func prepareUVScript(r *caseRun, options uvConfigCase, original map[string][]byte, hits *atomic.Int32) ([]string, string, error) {
	path := filepath.Join(r.WorkDir, "script.py")
	dependency := strconv.Quote(r.Candidate.Project + " @ " + firstUVArtifact(r.Candidate))
	if options.metadata {
		dependency = strconv.Quote(r.Candidate.Project + "==" + r.Candidate.Version)
	}
	if options.reject {
		dependency = ""
	}
	proxy := ""
	if strings.HasPrefix(options.name, "inline-") {
		key := "https-proxy"
		if options.name == "inline-http" {
			key = "http-proxy"
		}
		proxy = "# " + key + " = \"http://127.0.0.1:9\"\n"
	}
	raw, err := os.ReadFile("testdata/uv_config_scripts/script.py.tmpl")
	if err != nil {
		return nil, "", err
	}
	content, err := uvRender(string(raw), map[string]string{"Dependency": dependency, "Proxy": proxy})
	if err != nil {
		return nil, "", err
	}
	switch options.name {
	case "oversized-script":
		content = append(content, bytes.Repeat([]byte("#"), 16<<20)...)
	case "malformed-script":
		content, err = os.ReadFile("testdata/uv_config_scripts/malformed.py")
		if err != nil {
			return nil, "", err
		}
	}
	if err := uvWriteSnapshot(path, content, original); err != nil {
		return nil, "", err
	}
	target := "script.py"
	args := []string{"lock", "--script", target}
	switch options.name {
	case "symlink-script":
		if err := os.Symlink(path, filepath.Join(r.WorkDir, "linked.py")); err != nil {
			return nil, "", err
		}
		args[2] = "linked.py"
	case "inline-no-config":
		args = append(args, "--no-config")
	case "inline-explicit-config":
		config := filepath.Join(r.WorkDir, "explicit.toml")
		if err := uvWriteSnapshot(config, []byte("# empty\n"), original); err != nil {
			return nil, "", err
		}
		args = append(args, "--config-file", "explicit.toml")
	case "stdin-script":
		args[2] = "-"
	case "remote-script":
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write(content) }))
		// The only controlled origin serves a rejected script, never package artifacts.
		go func() { <-r.Context.Done(); server.Close() }()
		args[2] = server.URL + "/script.py"
	}
	lock := path + ".lock"
	if options.name == "symlink-script" {
		lock = filepath.Join(r.WorkDir, "linked.py.lock")
	}
	return args, lock, nil
}

func firstUVArtifact(c candidate) string {
	if len(c.Artifacts) == 0 {
		return ""
	}
	return c.Artifacts[0].URL
}

func prepareUVConfiguration(r *caseRun, options uvConfigCase, original map[string][]byte) ([]string, error) {
	good, bad := "https://pypi.org/simple", "http://127.0.0.1:9/simple"
	write := func(path, fixture, index string) error {
		content, err := uvFixture(fixture, map[string]string{"Index": index, "Name": "member"})
		if err != nil {
			return err
		}
		return uvWriteSnapshot(path, content, original)
	}
	venv := filepath.Join(r.Root, "venv")
	if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
		return nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	args := []string{"pip", "install", "--python", filepath.Join(venv, "bin", "python"), r.Candidate.Project + "==" + r.Candidate.Version}
	local := filepath.Join(r.WorkDir, "uv.toml")
	fixture := "registry"
	if options.merged {
		fixture = "proxy"
	}
	switch options.name {
	case "pyproject":
		return args, write(filepath.Join(r.WorkDir, "pyproject.toml"), "project", good)
	case "uv-over-pyproject":
		if err := write(filepath.Join(r.WorkDir, "pyproject.toml"), "project", bad); err != nil {
			return nil, err
		}
	case "user-project":
		if err := write(filepath.Join(r.Env["XDG_CONFIG_HOME"], "uv", "uv.toml"), "registry", bad); err != nil {
			return nil, err
		}
	case "explicit-config", "environment-config", "merged-explicit":
		if err := write(local, "registry", bad); err != nil {
			return nil, err
		}
		local = filepath.Join(r.WorkDir, "config", "selected.toml")
		if options.name == "environment-config" {
			r.Env["UV_CONFIG_FILE"] = local
		} else {
			args = append(args, "--config-file", "config/selected.toml")
		}
	case "environment-index", "cli-index", "no-config-cli", "no-config-env":
		if err := write(local, "registry", bad); err != nil {
			return nil, err
		}
		switch options.name {
		case "environment-index":
			r.Env["UV_INDEX_URL"] = good
		case "cli-index":
			r.Env["UV_INDEX_URL"] = bad
			args = append(args, "--index-url", good)
		case "no-config-cli":
			args = append(args, "--no-config")
		case "no-config-env":
			r.Env["UV_NO_CONFIG"] = "true"
		}
		return args, nil
	case "relative-directory", "symlink-parent", "working-directory-env", "working-directory-legacy-env", "merged-symlink":
		actual := filepath.Join(r.WorkDir, "physical")
		nested := filepath.Join(actual, "nested")
		if err := os.MkdirAll(nested, 0700); err != nil {
			return nil, err
		}
		if err := write(local, "registry", bad); err != nil {
			return nil, err
		}
		local = filepath.Join(actual, "uv.toml")
		switch options.name {
		case "relative-directory":
			args = append(args, "--directory", "physical/nested")
		case "working-directory-env":
			r.Env["UV_WORKING_DIR"] = nested
		case "working-directory-legacy-env":
			r.Env["UV_WORKING_DIRECTORY"] = nested
		default:
			if err := os.Symlink(nested, filepath.Join(r.WorkDir, "linked")); err != nil {
				return nil, err
			}
			args = append(args, "--directory", "linked/..")
		}
	case "workspace", "workspace-exclusion", "merged-workspace":
		member := filepath.Join(r.WorkDir, "packages", "nested", "member")
		rootFixture, rootIndex, memberIndex := "workspace", good, bad
		if options.name == "workspace-exclusion" {
			rootFixture, rootIndex, memberIndex = "excluded", bad, good
		}
		if err := write(filepath.Join(r.WorkDir, "pyproject.toml"), rootFixture, rootIndex); err != nil {
			return nil, err
		}
		if err := write(filepath.Join(member, "pyproject.toml"), "project", memberIndex); err != nil {
			return nil, err
		}
		args = append(args, "--directory", "packages/nested/member")
		if !options.merged {
			return args, nil
		}
	}
	return args, write(local, fixture, good)
}

func recordUVObservation(r *caseRun, state uvConfigState, statePath string, argv []string, command commandEvidence) error {
	r.Result.SCFWExit, r.Result.SCFWSignal = state.Exit, ""
	observerExit := state.Exit
	if state.Exit < 0 {
		// Python returns -signal for the child, then exits with 128+signal.
		// Match the normal Go command evidence convention for SCFW itself.
		r.Result.SCFWExit = -1
		r.Result.SCFWSignal = syscall.Signal(-state.Exit).String()
		observerExit = 128 - state.Exit
	}
	r.Result.Observations["invocation"] = state
	if err := r.Keep("process-observation", statePath); err != nil {
		return err
	}
	if !slices.Equal(state.Argv, argv) || observerExit != command.ExitCode {
		return fmt.Errorf("observer did not preserve SCFW invocation/exit")
	}
	return nil
}

func TestHarnessUVObserverExit(t *testing.T) {
	for _, test := range []struct {
		name                         string
		exit, observerExit, wantExit int
		wantSignal                   string
		mismatch                     bool
	}{
		{name: "success", exit: 0, observerExit: 0, wantExit: 0},
		{name: "native-failure", exit: 2, observerExit: 2, wantExit: 2},
		{name: "killed", exit: -int(syscall.SIGKILL), observerExit: 128 + int(syscall.SIGKILL), wantExit: -1, wantSignal: syscall.SIGKILL.String()},
		{name: "terminated", exit: -int(syscall.SIGTERM), observerExit: 128 + int(syscall.SIGTERM), wantExit: -1, wantSignal: syscall.SIGTERM.String()},
		{name: "corrupt-observer-exit", exit: -int(syscall.SIGKILL), observerExit: 0, wantExit: -1, wantSignal: syscall.SIGKILL.String(), mismatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			argv := []string{"/real/scfw", "run", "--", "uv", "lock"}
			state := uvConfigState{Argv: argv, Exit: test.exit}
			statePath := filepath.Join(root, "observed.json")
			if err := writeJSON(statePath, state); err != nil {
				t.Fatal(err)
			}
			r := &caseRun{Result: &result{SCFWSignal: "stale", Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}}
			err := recordUVObservation(r, state, statePath, argv, commandEvidence{ExitCode: test.observerExit})
			if (err != nil) != test.mismatch {
				t.Fatalf("unexpected observer assertion: %v", err)
			}
			if r.Result.SCFWExit != test.wantExit || r.Result.SCFWSignal != test.wantSignal {
				t.Fatalf("SCFW exit=%d signal=%q; want %d %q", r.Result.SCFWExit, r.Result.SCFWSignal, test.wantExit, test.wantSignal)
			}
			if r.Result.Evidence["process-observation"].SHA256 == "" {
				t.Fatal("missing observation evidence")
			}
			observation, ok := r.Result.Observations["invocation"].(uvConfigState)
			if !ok || observation.Exit != test.exit {
				t.Fatal("original SCFW observation was lost")
			}
		})
	}
}
