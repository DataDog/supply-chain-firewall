//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"
)

const uvCommandFixtures = "testdata/uv_commands"

type uvCommandCase struct {
	Operation                            string
	Block, Metadata, Direct, NativeError bool
}

func init() {
	discoverers["uv-commands"] = discoverUVCommands
	revalidators["uv-commands"] = revalidateUVCommands
	add := func(id, variant string, options uvCommandCase) {
		capabilities := []string{"public-network"}
		if strings.HasPrefix(options.Operation, "seed-") {
			capabilities = append(capabilities, "uv-seed-pip-only")
		}
		suites["uv-commands"] = append(suites["uv-commands"], scenario{
			Scenario: id, Variant: variant, Manager: "uv", Mode: "proxy", Backend: "local", RegistryProfile: "public-pypi",
			DiscoveryKey: "uv-commands", Capabilities: capabilities, Timeout: 4 * time.Minute,
			Run: func(r *caseRun) error { return runUVCommand(r, options) },
		})
	}
	for _, op := range []string{"pip-sync", "pip-compile", "add", "remove", "sync", "lock", "export", "tree", "build", "version-bump", "version-value", "version-no-sync", "seed-flag", "seed-env"} {
		id := "UV-02"
		if strings.HasPrefix(op, "pip-") {
			id = "UV-01"
		}
		if strings.HasPrefix(op, "version-") || strings.HasPrefix(op, "seed-") {
			id = "UV-04"
		}
		for _, block := range []bool{false, true} {
			outcome := "allow"
			if block {
				outcome = "block"
			}
			add(id, op+"-"+outcome, uvCommandCase{Operation: op, Block: block})
		}
	}
	for _, op := range []string{"pip-compile", "lock", "export", "tree"} {
		id := "UV-02"
		if op == "pip-compile" {
			id = "UV-01"
		}
		add(id, op+"-index-metadata-only", uvCommandCase{Operation: op, Metadata: true})
	}
	for _, op := range []string{"version-read", "version-dry-run", "version-frozen", "version-frozen-env", "venv-unseeded"} {
		add("UV-04", op, uvCommandCase{Operation: op, Direct: true})
	}
	add("CORE-14", "native-prefetch-rejection", uvCommandCase{Operation: "native-invalid", NativeError: true})
	add("CORE-14", "native-build-failure", uvCommandCase{Operation: "build", NativeError: true})
}

func discoverUVCommands(ctx context.Context, c cell, output string) (candidate, error) {
	selected, err := discoverPyPIOld(ctx, c, filepath.Join(output, "dependency"))
	if err != nil {
		return candidate{}, err
	}
	selected.Related = map[string]candidate{}
	for key, name := range map[string]string{"backend": "flit-core", "seed": "pip"} {
		var project pypiMetadata
		ev, err := fetchJSON(ctx, "https://pypi.org/pypi/"+name+"/json", filepath.Join(output, name+".json"), &project)
		if err != nil {
			return candidate{}, err
		}
		var versions []string
		for version := range project.Releases {
			if regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(version) {
				versions = append(versions, version)
			}
		}
		slices.SortFunc(versions, func(a, b string) int { return uvVersionCompare(b, a) })
		for _, version := range versions {
			var chosen pypiFile
			for _, file := range project.Releases[version] {
				if eligiblePipGraphFile(file, c, selected.ObservedAt) {
					chosen = file
					break
				}
			}
			if chosen.Filename == "" {
				continue
			}
			var release uvReleaseMetadata
			releaseEv, err := fetchJSON(ctx, "https://pypi.org/pypi/"+name+"/"+version+"/json", filepath.Join(output, name+"-"+version+".json"), &release)
			if err != nil {
				return candidate{}, err
			}
			if len(release.Info.RequiresDist) != 0 {
				continue
			}
			node := pipGraphCandidate(name, version, strings.ReplaceAll(name, "-", "_"), chosen, releaseEv, selected.ObservedAt)
			node.Metadata = append(node.Metadata, ev)
			selected.Related[key] = node
			break
		}
		if selected.Related[key].Project == "" {
			return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no old dependency-free %s wheel", name))
		}
	}
	selected.Constraints = append(selected.Constraints, "backend and seed versions frozen before SCFW; seed exclude-newer is discovery observation minus 48h")
	return selected, nil
}
func revalidateUVCommands(ctx context.Context, c candidate, output string) error {
	if err := revalidatePyPI(ctx, c, filepath.Join(output, "dependency")); err != nil {
		return err
	}
	for _, key := range []string{"backend", "seed"} {
		node, ok := c.Related[key]
		if !ok {
			return fmt.Errorf("missing %s pin", key)
		}
		if err := validateCandidate(node, time.Now().UTC()); err != nil {
			return err
		}
		if err := revalidatePyPI(ctx, node, filepath.Join(output, key)); err != nil {
			return err
		}
	}
	return nil
}

type uvCommandState struct {
	Version       string            `json:"version"`
	Dependencies  []string          `json:"dependencies"`
	Lock          map[string]string `json:"lock"`
	LockArtifacts []string          `json:"lock_artifacts"`
	Installed     map[string]string `json:"installed"`
	Compiled      string            `json:"compiled"`
	Wheels        map[string]string `json:"wheels"`
	Venv          bool              `json:"venv"`
}

func uvCommandTarget(c candidate, options uvCommandCase) candidate {
	if options.Operation == "build" {
		return c.Related["backend"]
	}
	if strings.HasPrefix(options.Operation, "seed-") {
		return c.Related["seed"]
	}
	return c
}
func prepareUVCommand(r *caseRun, options uvCommandCase) ([]string, error) {
	if _, _, err := prepareUV(r, uvOptions{flag: "1"}); err != nil {
		return nil, err
	}
	// Python 3.12+ seeds pip alone. Older interpreters need a separate
	// multi-package seed contract rather than silently ignoring extra downloads.
	if strings.HasPrefix(options.Operation, "seed-") && uvVersionCompare(r.Cell.RuntimeVersion, "3.12") < 0 {
		return nil, fmt.Errorf("uv-seed-pip-only capability requires Python >=3.12")
	}
	c := r.Candidate
	requirement := c.Project + " @ " + c.Artifacts[0].URL + "#sha256=" + c.Artifacts[0].SHA256
	if options.Metadata {
		requirement = c.Project + "==" + c.Version
	}
	dependencies := []string{requirement}
	if options.Operation == "add" {
		dependencies = nil
	}
	if options.Operation == "remove" {
		dependencies = append(dependencies, c.Related["backend"].Project+"=="+c.Related["backend"].Version)
	}
	backend := ""
	if options.Operation == "build" {
		dependencies = nil
		backend = c.Related["backend"].Project + "==" + c.Related["backend"].Version
	}
	tmpl, err := template.ParseFiles(filepath.Join(uvCommandFixtures, "configurations.toml.tmpl"))
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	values := map[string]any{"Python": r.Cell.RuntimeVersion, "Dependencies": dependencies, "Backend": backend}
	if err := tmpl.Execute(&body, values); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(r.WorkDir, "pyproject.toml"), body.Bytes(), 0600); err != nil {
		return nil, err
	}
	if options.Operation == "build" && !options.NativeError {
		source, err := os.ReadFile(filepath.Join(uvCommandFixtures, "module.py"))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(r.WorkDir, "scfw_uv_command.py"), source, 0600); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(r.WorkDir, "requirements.in"), []byte(requirement+"\n"), 0600); err != nil {
		return nil, err
	}
	r.Result.Observations["seed_exclude_newer"] = c.ObservedAt.Add(-48 * time.Hour).Format(time.RFC3339)
	switch options.Operation {
	case "pip-sync":
		if _, err := r.Command("prepare-venv", r.Cell.Runtime, "-m", "venv", "--without-pip", filepath.Join(r.WorkDir, ".venv")); err != nil {
			return nil, err
		}
		return []string{"pip", "sync", "requirements.in", "--python", filepath.Join(r.WorkDir, ".venv", "bin", "python")}, nil
	case "pip-compile":
		return []string{"pip", "compile", "requirements.in", "--output-file", "compiled.txt", "--no-header", "--no-annotate"}, nil
	case "add":
		return []string{"add", requirement}, nil
	case "remove":
		return []string{"remove", c.Related["backend"].Project}, nil
	case "sync":
		return []string{"sync", "--no-install-project"}, nil
	case "lock":
		return []string{"lock"}, nil
	case "export":
		return []string{"export", "--no-header", "--no-annotate", "--no-emit-project", "--output-file", "compiled.txt"}, nil
	case "tree":
		return []string{"tree"}, nil
	case "build":
		return []string{"build", "--wheel"}, nil
	case "version-bump":
		return []string{"version", "--bump", "patch"}, nil
	case "version-value":
		return []string{"version", "2.3.4"}, nil
	case "version-no-sync":
		return []string{"version", "--bump", "patch", "--no-sync"}, nil
	case "version-read":
		return []string{"version"}, nil
	case "version-dry-run":
		return []string{"version", "--bump", "patch", "--dry-run"}, nil
	case "version-frozen":
		return []string{"version", "2.3.4", "--frozen"}, nil
	case "version-frozen-env":
		r.Env["UV_FROZEN"] = "1"
		return []string{"version", "2.3.4"}, nil
	case "venv-unseeded":
		return []string{"venv", ".venv"}, nil
	case "seed-flag", "seed-env":
		r.Env["UV_EXCLUDE_NEWER"] = c.ObservedAt.Add(-48 * time.Hour).Format(time.RFC3339)
		args := []string{"venv", ".venv"}
		if options.Operation == "seed-flag" {
			args = append(args, "--seed")
		} else {
			r.Env["UV_VENV_SEED"] = "1"
		}
		return args, nil
	case "native-invalid":
		return []string{"pip", "sync", "--scfw-e2e-invalid-option"}, nil
	}
	return nil, fmt.Errorf("unimplemented uv operation %s", options.Operation)
}

func inspectUVCommand(r *caseRun, label string) (uvCommandState, error) {
	var state uvCommandState
	script, err := filepath.Abs(filepath.Join(uvCommandFixtures, "inspect.py"))
	if err != nil {
		return state, err
	}
	ev, err := r.Command(label+"-state", r.Cell.Runtime, "-I", "-S", script, r.WorkDir)
	if err != nil {
		return state, err
	}
	if err := readJSON(ev.Stdout.Path, &state); err != nil {
		return state, err
	}
	for _, name := range []string{"pyproject.toml", "uv.lock", "compiled.txt"} {
		path := filepath.Join(r.WorkDir, name)
		if _, err := os.Stat(path); err == nil {
			if err := r.Keep(label+"-"+name, path); err != nil {
				return state, err
			}
		} else if !os.IsNotExist(err) {
			return state, err
		}
	}
	r.Result.Observations[label+"_state"] = state
	return state, nil
}

func assertUVCommandState(state uvCommandState, c candidate, options uvCommandCase, blocked bool) error {
	target := uvCommandTarget(c, options)
	installed := state.Installed[target.Project]
	if blocked {
		if installed != "" || len(state.Wheels) != 0 || state.Compiled != "" || len(state.Lock) != 0 {
			return fmt.Errorf("blocked artifact produced completed command output: %+v", state)
		}
		return nil
	}
	expectedVersion := "0.1.0"
	switch options.Operation {
	case "version-bump", "version-no-sync":
		expectedVersion = "0.1.1"
	case "version-value", "version-frozen", "version-frozen-env":
		expectedVersion = "2.3.4"
	}
	if state.Version != expectedVersion {
		return fmt.Errorf("project version=%s, want %s", state.Version, expectedVersion)
	}
	if options.NativeError {
		if len(state.Wheels) != 0 || installed != "" {
			return fmt.Errorf("native failure produced installed/build output")
		}
		return nil
	}
	wantInstall := slices.Contains([]string{"pip-sync", "add", "remove", "sync", "version-bump", "version-value", "seed-flag", "seed-env"}, options.Operation)
	if wantInstall && installed != target.Version {
		return fmt.Errorf("installed %s=%q, want %s", target.Project, installed, target.Version)
	}
	if !wantInstall && len(state.Installed) != 0 {
		return fmt.Errorf("non-install command installed packages: %+v", state.Installed)
	}
	if strings.HasPrefix(options.Operation, "seed-") && len(state.Installed) != 1 {
		return fmt.Errorf("unexpected seed packages: %+v", state.Installed)
	}
	if options.Direct {
		if len(state.Lock) != 0 || state.Compiled != "" || len(state.Wheels) != 0 {
			return fmt.Errorf("direct selector produced resolution output")
		}
		if (options.Operation == "venv-unseeded") != state.Venv {
			return fmt.Errorf("direct selector virtualenv state mismatch")
		}
		return nil
	}
	if options.Operation == "build" {
		if state.Wheels["scfw-uv-command"] != "0.1.0" || len(state.Wheels) != 1 {
			return fmt.Errorf("missing project wheel output")
		}
		return nil
	}
	if options.Operation == "pip-compile" || options.Operation == "export" {
		expected := c.Project + "==" + c.Version
		if !options.Metadata {
			expected = c.Artifacts[0].URL
		}
		if !strings.Contains(state.Compiled, expected) {
			return fmt.Errorf("compiled/exported output lacks exact selected requirement")
		}
	}
	if slices.Contains([]string{"add", "remove", "sync", "lock", "export", "tree", "version-bump", "version-value", "version-no-sync"}, options.Operation) {
		if state.Lock[c.Project] != c.Version {
			return fmt.Errorf("lock lacks selected exact package: %+v", state.Lock)
		}
		if !options.Metadata && !slices.Contains(state.LockArtifacts, c.Artifacts[0].SHA256) {
			return fmt.Errorf("lock lacks selected artifact SHA256")
		}
	}
	return nil
}

func runUVCommand(r *caseRun, options uvCommandCase) error {
	target := uvCommandTarget(r.Candidate, options)
	var nativeState uvCommandState
	var native commandEvidence
	for _, phase := range []string{"native", "scfw"} {
		run := *r
		run.Root = filepath.Join(r.Root, phase)
		run.WorkDir = filepath.Join(run.Root, "work")
		var err error
		run.Env, err = isolatedEnvironment(run.Root)
		if err != nil {
			return err
		}
		args, err := prepareUVCommand(&run, options)
		if err != nil {
			return classified("INFRASTRUCTURE_FAILURE", err)
		}
		if err := snapshotGraphEvidence(&run, phase+"-input", filepath.Join(run.WorkDir, "pyproject.toml")); err != nil {
			return err
		}
		blocked := phase == "scfw" && options.Block
		// Metadata-only cases carry the exact finding too: resolution alone must
		// not fabricate a distribution evaluation from a lock entry.
		if phase == "scfw" && (options.Block || options.Metadata) {
			if err := writeFinding(&run, "PyPI", target.Project, target.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		argv := append([]string{run.Cell.Executable}, args...)
		if phase == "scfw" {
			argv = uvFirewallArgs(&run, "uv", run.Cell.Executable, uvOptions{errorOnBlock: true}, args)
		}
		command, commandErr := run.Command(phase, argv...)
		if command.TimedOut || command.ExitCode < 0 {
			return classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("command launch: %v", commandErr))
		}
		failed := blocked || options.NativeError
		if (command.ExitCode != 0) != failed {
			return fmt.Errorf("%s %s exit=%d, expected failure=%t: %v", phase, options.Operation, command.ExitCode, failed, commandErr)
		}
		state, err := inspectUVCommand(&run, phase)
		if err != nil {
			return err
		}
		if err := assertUVCommandState(state, r.Candidate, options, blocked); err != nil {
			return fmt.Errorf("%s: %w", phase, err)
		}
		if phase == "native" {
			nativeState, native = state, command
			continue
		}
		if !blocked && !reflect.DeepEqual(nativeState, state) {
			return fmt.Errorf("SCFW output differs from independent native control: native=%+v SCFW=%+v", nativeState, state)
		}
		if options.Operation == "version-read" || options.Operation == "version-dry-run" {
			nativeOutput, err := os.ReadFile(native.Stdout.Path)
			if err != nil {
				return err
			}
			protectedOutput, err := os.ReadFile(command.Stdout.Path)
			if err != nil {
				return err
			}
			if err := assertUVCommandVersionOutput(nativeOutput, protectedOutput); err != nil {
				return err
			}
		}
		stderr, err := os.ReadFile(command.Stderr.Path)
		if err != nil {
			return err
		}
		if options.NativeError {
			nativeStderr, err := os.ReadFile(native.Stderr.Path)
			if err != nil {
				return err
			}
			diagnostic := "unexpected argument '--scfw-e2e-invalid-option'"
			if options.Operation == "build" {
				diagnostic = "No file/folder found for module scfw_uv_command"
			}
			if command.ExitCode != native.ExitCode || !strings.Contains(string(stderr), diagnostic) || !strings.Contains(string(nativeStderr), diagnostic) {
				return fmt.Errorf("native exit/diagnostic not preserved: native=%d SCFW=%d", native.ExitCode, command.ExitCode)
			}
		}
		noPolicy := options.Direct || options.Metadata || options.Operation == "native-invalid"
		if noPolicy {
			if err := assertUVNoPolicy(&run); err != nil {
				return err
			}
			r.Result.PolicyOutcome, r.Result.ResolvedAction = "NOT_OBSERVED", "ALLOW"
		} else if err := assertGraphPolicy(&run, []candidate{target}, blocked, false); err != nil {
			return err
		}
		if options.Direct {
			if err := assertUVNoProxy(&run, string(stderr)); err != nil {
				return err
			}
		} else if err := assertCleanup(&run, string(stderr)); err != nil {
			return err
		}
		if options.Operation == "tree" && !blocked {
			stdout, err := os.ReadFile(command.Stdout.Path)
			if err != nil {
				return err
			}
			if !strings.Contains(string(stdout), r.Candidate.Project+" v"+r.Candidate.Version) {
				return fmt.Errorf("tree output lacks selected package")
			}
		}
	}
	return nil
}

func TestHarnessUVCommandsInventory(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range suites["uv-commands"] {
		if seen[spec.Variant] || spec.Run == nil {
			t.Fatalf("invalid variant %s", spec.Variant)
		}
		seen[spec.Variant] = true
	}
	if len(seen) != 39 {
		t.Fatalf("variant inventory=%d, want 39", len(seen))
	}
}
func TestHarnessUVCommandsBlockedOutput(t *testing.T) {
	c := candidate{Project: "idna", Version: "1"}
	var states map[string]uvCommandState
	if err := readJSON(filepath.Join(uvCommandFixtures, "states.json"), &states); err != nil {
		t.Fatal(err)
	}
	for name, state := range states {
		err := assertUVCommandState(state, c, uvCommandCase{Operation: "sync"}, true)
		if (err == nil) != (name == "blocked") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Read-only selectors must preserve visible output as well as unchanged files.
// Otherwise a dropped command can look identical to a successful invocation.
func assertUVCommandVersionOutput(native, protected []byte) error {
	if len(bytes.TrimSpace(native)) == 0 || !bytes.Equal(native, protected) {
		return fmt.Errorf("read-only version output differs from nonempty native stdout: native=%q SCFW=%q", native, protected)
	}
	return nil
}

func TestHarnessUVCommandVersionOutput(t *testing.T) {
	var cases map[string]struct {
		Native, Protected string
		Valid             bool
	}
	if err := readJSON(filepath.Join(uvCommandFixtures, "responses.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			err := assertUVCommandVersionOutput([]byte(item.Native), []byte(item.Protected))
			if (err == nil) != item.Valid {
				t.Fatalf("stdout validation: %v; want valid=%t", err, item.Valid)
			}
		})
	}
}
