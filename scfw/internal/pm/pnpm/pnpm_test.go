// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

const (
	// fakePnpmVersionEnv makes the test binary act as `pnpm --version`.
	fakePnpmVersionEnv = "SCFW_TEST_FAKE_PNPM_VERSION"
	// fakePnpmRecordEnv names a file where the fake records its cwd and the
	// package-manager variables it received.
	fakePnpmRecordEnv = "SCFW_TEST_FAKE_PNPM_RECORD"
)

func TestMain(m *testing.M) {
	if version := os.Getenv(fakePnpmVersionEnv); version != "" {
		if record := os.Getenv(fakePnpmRecordEnv); record != "" {
			cwd, _ := os.Getwd()
			lines := []string{cwd}
			for _, item := range os.Environ() {
				lower := strings.ToLower(item)
				if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(lower, "pnpm_config_") || strings.HasPrefix(item, "COREPACK") {
					lines = append(lines, item)
				}
			}
			_ = os.WriteFile(record, []byte(strings.Join(lines, "\n")), 0600)
		}
		fmt.Println(version)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakePnpm(t *testing.T, version string) Pnpm {
	t.Helper()
	return fakePnpmNamed(t, "pnpm", version)
}

func fakePnpmNamed(t *testing.T, name, version string) Pnpm {
	t.Helper()
	t.Setenv(fakePnpmVersionEnv, version)
	manager, err := NewPnpm(context.Background(), name, os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	// Only NewPnpm runs the fake; later processes must not inherit it.
	t.Setenv(fakePnpmVersionEnv, "")
	return manager
}

// isolatePnpmEnvironment removes the host's pnpm, npm, proxy, and trust
// settings and enters <root>/parent/project, with HOME, PREFIX and the XDG
// directories under root.
func isolatePnpmEnvironment(t *testing.T) string {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(lower, "pnpm_config_") || strings.HasSuffix(lower, "_proxy") ||
			strings.HasPrefix(key, "XDG_") || strings.HasPrefix(key, "COREPACK_") || lower == "proxy" ||
			key == "PNPM_HOME" || key == "NODE_EXTRA_CA_CERTS" || key == "GIT_SSL_CAINFO" || key == "PREFIX" || key == "DESTDIR" {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("PREFIX", filepath.Join(root, "prefix"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-config"))
	project := filepath.Join(root, "parent", "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	return root
}

// testdataDir is absolute because tests change directory before reading fixtures.
var testdataDir, _ = filepath.Abs("testdata")

// writePnpmFixture copies testdata/<fixture> to path, substituting args into
// .tmpl fixtures.
func writePnpmFixture(t *testing.T, path, fixture string, args ...any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, fixture))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.HasSuffix(fixture, ".tmpl") {
		content = fmt.Sprintf(content, args...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPnpmMajor(t *testing.T) {
	for version, want := range map[string]int{"10.34.9": 10, "11.28.9": 11, "12.18.0": 12} {
		isolatePnpmEnvironment(t)
		if got, err := fakePnpm(t, version).major(nil); err != nil || got != want {
			t.Errorf("%s: major = %d (error %v), want %d", version, got, err, want)
		}
	}
	for _, version := range []string{"9.15.9", "13.0.0", "not-a-version"} {
		isolatePnpmEnvironment(t)
		if _, err := fakePnpm(t, version).major(nil); !errors.Is(err, pm.ErrUnsupportedVersion) {
			t.Errorf("%s: error = %v, want ErrUnsupportedVersion", version, err)
		}
	}
	isolatePnpmEnvironment(t)
	manager, err := NewPnpm(context.Background(), "pnpm", filepath.Join(t.TempDir(), "missing-pnpm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.major(nil); !errors.Is(err, pm.ErrUnsupportedVersion) {
		t.Fatalf("missing executable: error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestPnpmMajorFollowsPin(t *testing.T) {
	for _, test := range []struct {
		name, installed string
		prepare         func(t *testing.T, root string)
		want            int
		unsupported     bool
	}{
		{name: "hash suffix", installed: "11.28.9", want: 12, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-12-hash.json")
		}},
		{name: "unsupported pin", installed: "11.28.9", unsupported: true, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-9.json")
		}},
		{name: "other package manager", installed: "11.28.9", want: 11, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/yarn.json")
		}},
		{name: "devEngines", installed: "10.34.9", want: 11, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/dev-engines-11.json")
		}},
		{name: "malformed manifest", installed: "11.28.9", want: 11, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/malformed.json")
		}},
		{name: "switching disabled by pmOnFail", installed: "11.28.9", want: 11, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-12.json")
			t.Setenv("pnpm_config_pm_on_fail", "ignore")
		}},
		{name: "switching disabled for pnpm 10", installed: "10.34.9", want: 10, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-12.json")
			t.Setenv("npm_config_manage_package_manager_versions", "false")
		}},
		{name: "installed 9 never switches", installed: "9.15.9", unsupported: true, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-12.json")
		}},
		{name: "workspace root pin from a member", installed: "12.18.0", want: 10, prepare: func(t *testing.T, root string) {
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-10.json")
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "pnpm-workspace.yaml"), "workspace-yaml/packages.yaml")
			member := filepath.Join(root, "parent", "project", "packages", "a")
			writePnpmFixture(t, filepath.Join(member, "package.json"), "manifest/member.json")
			t.Chdir(member)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolatePnpmEnvironment(t)
			test.prepare(t, root)
			got, err := fakePnpm(t, test.installed).major(nil)
			if test.unsupported {
				if !errors.Is(err, pm.ErrUnsupportedVersion) {
					t.Fatalf("error = %v, want ErrUnsupportedVersion", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("major = %d (error %v), want %d", got, err, test.want)
			}
		})
	}
}

// Each pnpm major honours different settings that stop the switch to a pinned
// version, so SCFW must not apply one major's settings to another.
func TestPnpmMajorSwitchingSettingsPerVersion(t *testing.T) {
	for _, test := range []struct {
		name, installed string
		command         []string
		env             map[string]string
		want            int
	}{
		{"pnpm 10 ignores pm_on_fail", "10.34.9", nil, map[string]string{"pnpm_config_pm_on_fail": "ignore"}, 12},
		{"pnpm 10 stops for corepack", "10.34.9", nil, map[string]string{"COREPACK_ROOT": "/corepack"}, 10},
		{"pnpm 11 ignores manage-package-manager-versions", "11.28.9", nil, map[string]string{"npm_config_manage_package_manager_versions": "false"}, 12},
		{"pnpm 11 command-line pm-on-fail", "11.28.9", []string{"--pm-on-fail=ignore", "add", "x"}, nil, 11},
		{"pnpm 11 with current runs the installed pnpm", "11.28.9", []string{"with", "current", "add", "x"}, nil, 11},
		{"pnpm 12 uppercase pm_on_fail", "12.18.0", nil, map[string]string{"PNPM_CONFIG_PM_ON_FAIL": "ignore"}, 12},
		{"pnpm 12 manage-package-manager-versions", "12.18.0", nil, map[string]string{"pnpm_config_manage_package_manager_versions": "false"}, 12},
		{"pnpm 12 config pm-on-fail", "12.18.0", []string{"--config.pm-on-fail=ignore", "add", "x"}, nil, 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolatePnpmEnvironment(t)
			pin := "manifest/pnpm-12.json"
			if test.installed == "12.18.0" {
				pin = "manifest/pnpm-10.json"
			}
			writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), pin)
			for key, value := range test.env {
				t.Setenv(key, value)
			}
			command := test.command
			if command == nil {
				command = []string{"add", "x"}
			}
			if got, err := fakePnpm(t, test.installed).major(command); err != nil || got != test.want {
				t.Fatalf("major = %d (error %v), want %d", got, err, test.want)
			}
		})
	}
}

// Running `pnpm --version` in a pinned project would download the pinned pnpm
// outside the proxy.
func TestNewPnpmProbesOutsideProject(t *testing.T) {
	root := isolatePnpmEnvironment(t)
	writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/pnpm-12.json")
	record := filepath.Join(t.TempDir(), "record")
	t.Setenv(fakePnpmRecordEnv, record)
	fakePnpm(t, "11.28.9")
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if cwd := lines[0]; strings.HasPrefix(cwd, root) || strings.HasPrefix(cwd, resolvedRoot) {
		t.Fatalf("probe ran in %s, inside the project tree %s", cwd, root)
	}
	for _, want := range []string{
		"npm_config_manage_package_manager_versions=false", "pnpm_config_manage_package_manager_versions=false",
		"pnpm_config_pm_on_fail=ignore", "npm_config_package_manager_strict=false", "COREPACK_ENABLE_STRICT=0",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("probe environment lacks %s", want)
		}
	}
	if _, err := os.Stat(lines[0]); !os.IsNotExist(err) {
		t.Errorf("probe directory %s was not removed", lines[0])
	}
}

// pnpx runs `pnpm dlx`, so `pnpx --version` fails; the version comes from the
// pnpm entry point beside it.
func TestNewPnpmProbesPnpmBesidePnpx(t *testing.T) {
	isolatePnpmEnvironment(t)
	manager, err := NewPnpm(context.Background(), "pnpx", filepath.Join(testdataDir, "bin", "pnpx"))
	if err != nil {
		t.Fatal(err)
	}
	if major, err := manager.major([]string{"cowsay"}); err != nil || major != 11 {
		t.Fatalf("major = %d (error %v), want 11 from the sibling pnpm", major, err)
	}
	if manager.Executable() != filepath.Join(testdataDir, "bin", "pnpx") {
		t.Fatalf("executable = %s, want pnpx itself to run the command", manager.Executable())
	}
}

func TestResolveInstallTargetsRequiresProxyMode(t *testing.T) {
	isolatePnpmEnvironment(t)
	_, err := fakePnpm(t, "11.28.9").ResolveInstallTargets(context.Background(), []string{"add", "x"})
	if err == nil || err.Error() != "pnpm package operations require proxy mode (set SCFW_PROXY_ENABLED=1)" {
		t.Fatalf("error = %v", err)
	}
}
