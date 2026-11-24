// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gateEnvironment isolates the gate from the host's pnpm configuration.
func gateEnvironment(t *testing.T) []string {
	t.Helper()
	root := t.TempDir()
	return []string{
		"HOME=" + filepath.Join(root, "home"),
		"XDG_CONFIG_HOME=" + filepath.Join(root, "xdg-config"),
	}
}

// gateProject writes a project with the manifest fixture and returns its
// directory.
func gateProject(t *testing.T, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	writePnpmFixture(t, filepath.Join(dir, "package.json"), manifest)
	return dir
}

// writeGateState writes the state fixture for dir, with dir as its first
// recorded project and any further projects after it.
func writeGateState(t *testing.T, dir, fixture string, timestamp int64, projects ...string) {
	t.Helper()
	args := []any{timestamp}
	for _, project := range append([]string{dir}, projects...) {
		args = append(args, project)
	}
	writePnpmFixture(t, filepath.Join(dir, "node_modules", ".pnpm-workspace-state-v1.json"), fixture, args...)
}

// installArtifacts leaves the lockfile and modules directory an install of
// dependencies writes.
func installArtifacts(t *testing.T, dir string) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(dir, "pnpm-lock.yaml"),
		filepath.Join(dir, "node_modules", ".pnpm", "lock.yaml"),
		filepath.Join(dir, "node_modules", "lab-pkg", "package.json"),
	} {
		writeGateFile(t, path, "")
	}
}

func writeGateFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func touchAfter(t *testing.T, path string, after time.Time) {
	t.Helper()
	if err := os.Chtimes(path, after.Add(time.Hour), after.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func scriptGate(major int, dir string, environ []string) bool {
	return installsBeforeScript(major, parseCommand(major, false, []string{"run", "hello"}), dir, environ)
}

// Each verifyDepsBeforeRun value decides alone, and every source overrides the
// ones after it: the pnpm_config_* variable, the command line, the workspace's
// pnpm-workspace.yaml, and the global config.yaml. The project below declares
// dependencies and was never installed, so an install action installs.
func TestInstallsBeforeScriptValues(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		env     [2]string
		want    bool
	}{
		{name: "default installs", want: true},
		{name: "env false", env: [2]string{"pnpm_config_verify_deps_before_run", "false"}, want: false},
		{name: "env warn", env: [2]string{"pnpm_config_verify_deps_before_run", "warn"}, want: false},
		{name: "env error", env: [2]string{"pnpm_config_verify_deps_before_run", "error"}, want: false},
		{name: "env true", env: [2]string{"pnpm_config_verify_deps_before_run", "true"}, want: false},
		{name: "env install", env: [2]string{"pnpm_config_verify_deps_before_run", "install"}, want: true},
		{name: "env prompt", env: [2]string{"pnpm_config_verify_deps_before_run", "prompt"}, want: true},
		{name: "env unknown value", env: [2]string{"pnpm_config_verify_deps_before_run", "sometimes"}, want: true},
		{name: "command line false", command: "--config.verify-deps-before-run=false run hello", want: false},
		{name: "env beats command line", command: "--config.verify-deps-before-run=false run hello",
			env: [2]string{"pnpm_config_verify_deps_before_run", "install"}, want: true},
		{name: "command line beats workspace", command: "--config.verify-deps-before-run=false run hello", want: false},
		{name: "workspace warn", want: false},
		{name: "workspace install", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			environ := gateEnvironment(t)
			dir := gateProject(t, "manifest/dependencies.json")
			if test.name == "command line beats workspace" || test.name == "workspace install" {
				writePnpmFixture(t, filepath.Join(dir, "pnpm-workspace.yaml"), "workspace-yaml/verify-deps-install.yaml")
			}
			if test.name == "workspace warn" {
				writePnpmFixture(t, filepath.Join(dir, "pnpm-workspace.yaml"), "workspace-yaml/verify-deps-warn.yaml")
			}
			command := strings.Fields("run hello")
			if test.command != "" {
				command = strings.Fields(test.command)
			}
			if test.env[0] != "" {
				environ = append(environ, test.env[0]+"="+test.env[1])
			}
			if got := installsBeforeScript(11, parseCommand(11, false, command), dir, environ); got != test.want {
				t.Errorf("installsBeforeScript = %v, want %v", got, test.want)
			}
		})
	}
}

// The gate only ever reports an install for pnpm 11 and 12: pnpm 10 has no
// verifyDepsBeforeRun gate enabled by default.
func TestInstallsBeforeScriptSkipsPnpm10(t *testing.T) {
	dir := gateProject(t, "manifest/dependencies.json")
	if got := scriptGate(10, dir, gateEnvironment(t)); got {
		t.Error("pnpm 10 never installs before a script")
	}
}

// pnpm skips the gate without a root project.
func TestInstallsBeforeScriptWithoutManifest(t *testing.T) {
	if got := scriptGate(11, t.TempDir(), gateEnvironment(t)); got {
		t.Error("a project without a manifest cannot install")
	}
}

// A missing state means an install unless no project declares a dependency and
// no pnpmfile hooks run, which is pnpm's fresh-project script.
func TestInstallsBeforeScriptMissingState(t *testing.T) {
	environ := gateEnvironment(t)
	if dir := gateProject(t, "manifest/dependencies.json"); scriptGate(11, dir, environ) != true {
		t.Error("dependencies without a state must install")
	}
	if dir := gateProject(t, "manifest/plain.json"); scriptGate(11, dir, environ) != false {
		t.Error("a project without dependencies has nothing to install")
	}
	dir := gateProject(t, "manifest/plain.json")
	writeGateFile(t, filepath.Join(dir, ".pnpmfile.cjs"), "")
	if scriptGate(11, dir, environ) != true {
		t.Error("a pnpmfile can add dependencies, so pnpm installs")
	}
}

// The state's timestamp proves the project current until a file pnpm compares
// changes after it; an equal-millisecond change is the install itself.
func TestInstallsBeforeScriptFreshness(t *testing.T) {
	// The install happened after everything it wrote, so nothing compares as
	// newer than the timestamp it recorded.
	timestamp := time.Now().Add(time.Hour).UnixMilli()
	for _, test := range []struct {
		name   string
		fresh  bool
		change func(t *testing.T, dir string)
	}{
		{name: "fresh state", fresh: true},
		{name: "newer package.json", change: func(t *testing.T, dir string) {
			touchAfter(t, filepath.Join(dir, "package.json"), time.Now())
		}},
		{name: "newer lockfile", change: func(t *testing.T, dir string) {
			touchAfter(t, filepath.Join(dir, "pnpm-lock.yaml"), time.Now())
		}},
		{name: "newer workspace file", change: func(t *testing.T, dir string) {
			writePnpmFixture(t, filepath.Join(dir, "pnpm-workspace.yaml"), "workspace-yaml/verify-deps-install.yaml")
			touchAfter(t, filepath.Join(dir, "pnpm-workspace.yaml"), time.UnixMilli(timestamp))
		}},
		{name: "equal-millisecond mtime", fresh: true, change: func(t *testing.T, dir string) {
			exact := time.UnixMilli(timestamp)
			if err := os.Chtimes(filepath.Join(dir, "package.json"), exact, exact); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			environ := gateEnvironment(t)
			dir := gateProject(t, "manifest/dependencies.json")
			writeGateState(t, dir, "workspace-state/state.json.tmpl", timestamp)
			installArtifacts(t, dir)
			if test.change != nil {
				test.change(t, dir)
			}
			if got := scriptGate(11, dir, environ); got != !test.fresh {
				t.Errorf("installsBeforeScript = %v, want %v", got, !test.fresh)
			}
		})
	}
}

// A filtered install leaves some projects unverified, so pnpm reinstalls.
func TestInstallsBeforeScriptFilteredState(t *testing.T) {
	dir := gateProject(t, "manifest/dependencies.json")
	writeGateState(t, dir, "workspace-state/state-filtered.json.tmpl", time.Now().Add(time.Hour).UnixMilli())
	installArtifacts(t, dir)
	if got := scriptGate(11, dir, gateEnvironment(t)); got != true {
		t.Errorf("installsBeforeScript = %v, want a filtered state to install", got)
	}
}

// A workspace whose members the packages globs select: the state must record
// exactly the projects the globs find, every declaring member needs a modules
// directory, and patterns the matcher cannot reproduce cannot be decided.
func TestInstallsBeforeScriptWorkspace(t *testing.T) {
	timestamp := time.Now().Add(time.Hour).UnixMilli()
	for _, test := range []struct {
		name   string
		fresh  bool
		layout func(t *testing.T, root string)
	}{
		{name: "recorded members", fresh: true, layout: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "pnpm-workspace.yaml"), "workspace-yaml/packages.yaml")
			member := filepath.Join(root, "packages", "a")
			writePnpmFixture(t, filepath.Join(member, "package.json"), "manifest/plain.json")
			writeGateState(t, root, "workspace-state/state-two.json.tmpl", timestamp, member)
		}},
		{name: "added project", layout: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "pnpm-workspace.yaml"), "workspace-yaml/packages.yaml")
			member := filepath.Join(root, "packages", "a")
			writePnpmFixture(t, filepath.Join(member, "package.json"), "manifest/plain.json")
			writeGateState(t, root, "workspace-state/state.json.tmpl", timestamp)
		}},
		{name: "missing member modules directory", layout: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "pnpm-workspace.yaml"), "workspace-yaml/packages.yaml")
			member := filepath.Join(root, "packages", "a")
			writePnpmFixture(t, filepath.Join(member, "package.json"), "manifest/dependencies.json")
			writeGateState(t, root, "workspace-state/state-two.json.tmpl", timestamp, member)
		}},
		{name: "negation glob", layout: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "pnpm-workspace.yaml"), "workspace-yaml/packages-negation.yaml")
			writeGateState(t, root, "workspace-state/state.json.tmpl", timestamp)
		}},
		{name: "brace glob", layout: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "pnpm-workspace.yaml"), "workspace-yaml/packages-braces.yaml")
			writeGateState(t, root, "workspace-state/state.json.tmpl", timestamp)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			environ := gateEnvironment(t)
			dir := gateProject(t, "manifest/dependencies.json")
			installArtifacts(t, dir)
			test.layout(t, dir)
			if got := scriptGate(12, dir, environ); got != !test.fresh {
				t.Errorf("installsBeforeScript = %v, want %v", got, !test.fresh)
			}
		})
	}
}

// Layouts the checks cannot reproduce are proxied rather than decided.
func TestInstallsBeforeScriptUndecidableLayouts(t *testing.T) {
	for _, test := range []struct {
		name  string
		major int
		key   string
		value string
	}{
		{name: "workspace lockfileDir", major: 11, key: "lockfileDir", value: "elsewhere"},
		{name: "workspace modulesDir", major: 12, key: "modulesDir", value: "elsewhere"},
		{name: "workspace per-project lockfiles", major: 12, key: "sharedWorkspaceLockfile", value: "false"},
		{name: "workspace git branch lockfiles", major: 12, key: "gitBranchLockfile", value: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			environ := gateEnvironment(t)
			dir := gateProject(t, "manifest/dependencies.json")
			writeGateState(t, dir, "workspace-state/state.json.tmpl", time.Now().Add(time.Hour).UnixMilli())
			installArtifacts(t, dir)
			writePnpmFixture(t, filepath.Join(dir, "pnpm-workspace.yaml"), "workspace-yaml/setting.yaml.tmpl", test.key, test.value)
			if got := scriptGate(test.major, dir, environ); got != true {
				t.Errorf("installsBeforeScript = %v, want the layout proxied", got)
			}
		})
	}
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "command-line lockfile-dir", command: "--config.lockfile-dir=elsewhere run hello"},
		{name: "command-line modules-dir", command: "--config.modules-dir=elsewhere run hello"},
		{name: "command-line per-project lockfiles", command: "--config.shared-workspace-lockfile=false run hello"},
		{name: "command-line git branch lockfiles", command: "--config.git-branch-lockfile=true run hello"},
	} {
		t.Run(test.name, func(t *testing.T) {
			environ := gateEnvironment(t)
			dir := gateProject(t, "manifest/dependencies.json")
			writeGateState(t, dir, "workspace-state/state.json.tmpl", time.Now().Add(time.Hour).UnixMilli())
			installArtifacts(t, dir)
			if got := installsBeforeScript(12, parseCommand(12, false, strings.Fields(test.command)), dir, environ); got != true {
				t.Errorf("installsBeforeScript = %v, want the layout proxied", got)
			}
		})
	}
}
