// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func workspaceFixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/workspace-resolution/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var files map[string]json.RawMessage
	if err := json.Unmarshal(data, &files); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	snapshots := map[string][]byte{}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		snapshots[path] = bytes.Clone(content)
	}
	if err := os.WriteFile(filepath.Join(root, "private-source.txt"), []byte("must not copy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"member", "shared"} {
		if err := os.Symlink("../packages/"+member, filepath.Join(root, "node_modules", member)); err != nil {
			t.Fatal(err)
		}
	}
	return root, snapshots
}

func runNpmWorkspaceFixture(args []string) int {
	if fixture := os.Getenv("SCFW_TEST_NPM_VERSIONLESS_WORKSPACE"); fixture != "" {
		if len(args) > 0 && args[0] == "prefix" {
			cwd, _ := os.Getwd()
			fmt.Println(cwd)
			return 0
		}
		if len(args) > 0 && args[0] == "config" {
			fmt.Println(`{"global":false}`)
			return 0
		}
		if _, err := os.Stat("packages/member/package.json"); err != nil {
			return 1
		}
		if slices.Contains(args, "--package-lock-only") {
			content, err := os.ReadFile(fixture)
			if err != nil || os.WriteFile("package-lock.json", content, 0600) != nil {
				return 1
			}
		} else {
			fmt.Fprintln(os.Stderr, "npm silly ADD node_modules/member\nnpm silly ADD node_modules/is-number")
		}
		return 0
	}
	if os.Getenv("SCFW_TEST_NPM_WORKSPACE_DISABLED") != "" {
		return runNpmDisabledWorkspaceFixture(args)
	}
	if len(args) > 0 && args[0] == "prefix" {
		wd, err := os.Getwd()
		if err != nil {
			return 1
		}
		if root := os.Getenv("SCFW_TEST_NPM_WORKSPACE_ROOT"); root != "" {
			wd = root
		}
		fmt.Println(wd)
		return 0
	}
	if len(args) > 0 && args[0] == "config" {
		if slices.Contains(args, "--workspace") || slices.Contains(args, "-w") {
			return 1
		}
		fmt.Println(`{"omit":["dev"],"include":[]}`)
		return 0
	}
	cwd, _ := os.Getwd()
	root := cwd
	for {
		if _, err := os.Stat(filepath.Join(root, "packages/member/package.json")); err == nil {
			break
		}
		if filepath.Dir(root) == root {
			return 0
		}
		root = filepath.Dir(root)
	}
	production := "production"
	if os.Getenv("SCFW_TEST_NPM_WORKSPACE_ROOT") != "" && cwd != filepath.Join(root, "packages/member") {
		production = "other-workspace"
	}

	if !slices.Contains(args, "--ignore-scripts") {
		return 1
	}
	if slices.Contains(args, "--package-lock-only") {
		if err := os.WriteFile(filepath.Join(root, "packages/member/package.json"), []byte(`{"name":"changed-only-in-copy"}`), 0600); err != nil {
			return 1
		}
		if err := writeNpmJSONFile(filepath.Join(root, "package-lock.json"), map[string]any{"packages": map[string]any{
			"node_modules/" + production: map[string]any{"version": "1.0.0"},
			"node_modules/development":   map[string]any{"version": "1.0.0", "dev": true},
		}}); err != nil {
			return 1
		}
	} else {
		fmt.Fprintln(os.Stderr, "npm silly ADD node_modules/"+production)
		fmt.Fprintln(os.Stderr, "npm silly ADD node_modules/development")
	}
	return 0
}

func TestNpmWorkspaceResolutionIsolated(t *testing.T) {
	for _, command := range [][]string{{"install", "--production"}, {"install", "--workspace", "member", "--production"}, {"install", "-w", "member", "--production"}} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			manager := fixtureNpm(t)
			root, snapshots := workspaceFixture(t)
			t.Setenv("SCFW_TEST_NPM_WORKSPACE", "1")
			t.Chdir(root)
			targets, err := manager.ResolveInstallTargets(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			names := []string{}
			for pkg := range targets.Items() {
				names = append(names, pkg.Name)
			}
			if !slices.Equal(names, []string{"production"}) {
				t.Fatalf("workspace targets=%v, want production", names)
			}
			for path, want := range snapshots {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("source changed: %s: %v", path, err)
				}
			}
		})
	}
}

func TestNpmWorkspaceCopyPreservesLocalLinks(t *testing.T) {
	root, _ := workspaceFixture(t)
	unrelated := filepath.Join(root, "unrelated-fixture")
	if err := os.Mkdir(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unrelated, "package.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}

	temp := t.TempDir()
	p := npmTempProject{projectRoot: root, dir: temp}
	if err := p.copyProjectFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(temp, "private-source.txt")); !os.IsNotExist(err) {
		t.Fatal("copied unrelated source")
	}
	for _, member := range []string{"member", "shared"} {
		actual, err := filepath.EvalSymlinks(filepath.Join(temp, "node_modules", member))
		if err != nil {
			t.Fatal(err)
		}
		if actual != filepath.Join(temp, "packages", member) {
			t.Fatalf("workspace symlink points outside copy: %s", actual)
		}
	}
	manifest, err := readNpmJSONFile(filepath.Join(temp, "packages/member/package.json"))
	if err != nil {
		t.Fatal(err)
	}
	deps := manifest["dependencies"].(map[string]any)
	if deps["shared"] != "file:../shared" {
		t.Fatalf("relative workspace dependency changed: %v", deps)
	}
	rootManifest, err := readNpmJSONFile(filepath.Join(temp, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rootManifest["dependencies"].(map[string]any)["member"] != "file:packages/member" {
		t.Fatal("root local workspace reference escaped copy")
	}
	lock, err := readNpmJSONFile(filepath.Join(temp, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	packages := lock["packages"].(map[string]any)
	if packages["packages/member"] == nil || packages["packages/shared"] == nil {
		t.Fatal("workspace lock topology was not preserved")
	}
	nested, ok := packages["packages/member/node_modules/production"].(map[string]any)
	if !ok || nested["version"] != "1.0.0" {
		t.Fatalf("nested workspace lock entry changed: %v", packages)
	}
}

func TestNpmWorkspaceMemberDirectorySelection(t *testing.T) {
	manager := fixtureNpm(t)
	root, snapshots := workspaceFixture(t)
	t.Setenv("SCFW_TEST_NPM_WORKSPACE", "1")
	t.Setenv("SCFW_TEST_NPM_WORKSPACE_ROOT", root)
	t.Chdir(filepath.Join(root, "packages/member"))
	targets, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "--production"})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for pkg := range targets.Items() {
		names = append(names, pkg.Name)
	}
	if !slices.Equal(names, []string{"production"}) {
		t.Fatalf("member invocation selected %v, want production", names)
	}
	for path, want := range snapshots {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("source changed: %s: %v", path, err)
		}
	}
}

// A disabled member install owns its lockfile even when a different version
// of the same package occurs in the enclosing workspace root lockfile.
func runNpmDisabledWorkspaceFixture(args []string) int {
	if len(args) > 0 && args[0] == "config" {
		fmt.Println(`{"global":false}`)
		return 0
	}
	cwd, _ := os.Getwd()
	if len(args) > 0 && args[0] == "prefix" {
		root := os.Getenv("SCFW_TEST_NPM_WORKSPACE_ROOT")
		for _, option := range parseNpmOptions(args) {
			if option.name == "workspaces" && option.value == "false" {
				root = cwd
			}
		}
		fmt.Println(root)
		return 0
	}
	if slices.Contains(args, "--package-lock-only") {
		if err := writeNpmJSONFile(filepath.Join(cwd, "package-lock.json"), map[string]any{"packages": map[string]any{"node_modules/react": map[string]any{"version": "18.3.0"}}}); err != nil {
			return 1
		}
	} else {
		fmt.Fprintln(os.Stderr, "npm silly ADD node_modules/react")
	}
	return 0
}

func TestNpmWorkspaceDisabledUsesMemberLock(t *testing.T) {
	for _, flags := range [][]string{{"--workspaces=false"}, {"--workspaces", "false"}, {"--no-workspaces"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			manager := fixtureNpm(t)
			root, snapshots := workspaceFixture(t)
			lock := filepath.Join(root, "package-lock.json")
			if err := writeNpmJSONFile(lock, map[string]any{"packages": map[string]any{"node_modules/react": map[string]any{"version": "17.0.0"}}}); err != nil {
				t.Fatal(err)
			}
			snapshots[lock], _ = os.ReadFile(lock)
			t.Setenv("SCFW_TEST_NPM_WORKSPACE", "1")
			t.Setenv("SCFW_TEST_NPM_WORKSPACE_DISABLED", "1")
			t.Setenv("SCFW_TEST_NPM_WORKSPACE_ROOT", root)
			t.Chdir(filepath.Join(root, "packages/member"))
			targets, err := manager.ResolveInstallTargets(context.Background(), append([]string{"install", "--ignore-scripts"}, flags...))
			if err != nil {
				t.Fatal(err)
			}
			if targets.Len() != 1 {
				t.Fatalf("targets = %v", targets)
			}
			for pkg := range targets.Items() {
				if pkg.Name != "react" || pkg.Version != "18.3.0" {
					t.Fatalf("evaluated %s@%s, want member react@18.3.0", pkg.Name, pkg.Version)
				}
			}
			for path, want := range snapshots {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("source changed: %s: %v", path, err)
				}
			}
		})
	}
}

func TestNpmWorkspaceVersionlessMember(t *testing.T) {
	manager := fixtureNpm(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "packages/member"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]map[string]any{
		"package.json":                 {"name": "root", "private": true, "workspaces": []string{"packages/*"}},
		"packages/member/package.json": {"name": "member", "private": true, "dependencies": map[string]string{"is-number": "6.0.0"}},
	}
	for name, manifest := range files {
		if err := writeNpmJSONFile(filepath.Join(root, name), manifest); err != nil {
			t.Fatal(err)
		}
	}
	fixture, err := filepath.Abs("testdata/workspace-resolution/versionless.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCFW_TEST_NPM_WORKSPACE", "1")
	t.Setenv("SCFW_TEST_NPM_VERSIONLESS_WORKSPACE", fixture)
	t.Chdir(root)
	targets, err := manager.ResolveInstallTargets(context.Background(), []string{"install"})
	if err != nil {
		t.Fatal(err)
	}
	if targets.Len() != 2 {
		t.Fatalf("targets=%v, want local member and registry dependency", targets)
	}
	for pkg := range targets.Items() {
		switch pkg.Name {
		case "member":
			if pkg.Version != "" || !filepath.IsAbs(pkg.Source) {
				t.Fatalf("local versionless member=%+v", pkg)
			}
		case "is-number":
			if pkg.Version != "6.0.0" || pkg.Source != "https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz" {
				t.Fatalf("registry dependency=%+v", pkg)
			}
		default:
			t.Fatalf("unexpected target %+v", pkg)
		}
	}
	for name, want := range files {
		got, err := readNpmJSONFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := json.Marshal(got)
		expected, _ := json.Marshal(want)
		if !bytes.Equal(actual, expected) {
			t.Fatalf("source manifest changed: %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "package-lock.json")); !os.IsNotExist(err) {
		t.Fatalf("inspection wrote original lock: %v", err)
	}
}

func TestNpmWorkspaceCopySkipsUnrelatedDirectories(t *testing.T) {
	for _, workspaces := range []any{[]string{}, []string{"packages/*"}, map[string]any{"packages": []string{"{packages,tools}/*"}}} {
		t.Run(fmt.Sprint(workspaces), func(t *testing.T) {
			root, _ := workspaceFixture(t)
			manifest, err := readNpmJSONFile(filepath.Join(root, "package.json"))
			if err != nil {
				t.Fatal(err)
			}
			manifest["workspaces"] = workspaces
			if err := writeNpmJSONFile(filepath.Join(root, "package.json"), manifest); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"unrelated/private", "packages/member/private"} {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0700) })
				if _, err := os.ReadDir(path); !os.IsPermission(err) {
					t.Skip("directory permissions are not enforced")
				}
			}
			p := npmTempProject{projectRoot: root, dir: t.TempDir()}
			if err := p.copyProjectFiles(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNpmWorkspaceCopyIgnoresMemberLockfiles(t *testing.T) {
	root, _ := workspaceFixture(t)
	content, err := os.ReadFile("testdata/workspace-resolution/invalid-member-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "packages/member/package-lock.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	p := npmTempProject{projectRoot: root, dir: t.TempDir()}
	if err := p.copyProjectFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.dir, "packages/member/package-lock.json")); !os.IsNotExist(err) {
		t.Fatalf("member lockfile must remain ignored: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("member lockfile changed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.dir, "package-lock.json")); err != nil {
		t.Fatalf("root lockfile missing: %v", err)
	}
}

func TestNpmWorkspaceCopyAcceptsBOMManifest(t *testing.T) {
	root, _ := workspaceFixture(t)
	content, err := os.ReadFile("testdata/workspace-resolution/bom-member-package.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "packages/member/package.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	p := npmTempProject{projectRoot: root, dir: t.TempDir()}
	if err := p.copyProjectFiles(); err != nil {
		t.Fatal(err)
	}
	manifest, err := readNpmJSONFile(filepath.Join(p.dir, "packages/member/package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if manifest["name"] != "member" {
		t.Fatalf("member manifest not copied: %v", manifest)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("member manifest changed: %v", err)
	}
}

func TestNpmWorkspaceCopyPreservesPatternSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns any
		members  []string
	}{
		{"recursive", []string{"packages/**"}, []string{"member", "shared"}},
		{"recursive-prefix", []string{"**/packages/*"}, []string{"member", "shared"}},
		{"braces", []string{"{packages,tools}/{member,shared}"}, []string{"member", "shared"}},
		{"object", map[string]any{"packages": []string{"packages/*"}}, []string{"member", "shared"}},
		{"exclusion", []string{"packages/*", "!packages/shared"}, []string{"member"}},
		{"empty", []string{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := workspaceFixture(t)
			manifest, err := readNpmJSONFile(filepath.Join(root, "package.json"))
			if err != nil {
				t.Fatal(err)
			}
			manifest["workspaces"] = tc.patterns
			if err := writeNpmJSONFile(filepath.Join(root, "package.json"), manifest); err != nil {
				t.Fatal(err)
			}
			p := npmTempProject{projectRoot: root, dir: t.TempDir()}
			if err := p.copyProjectFiles(); err != nil {
				t.Fatal(err)
			}
			for _, member := range []string{"member", "shared"} {
				_, err := os.Stat(filepath.Join(p.dir, "packages", member, "package.json"))
				if slices.Contains(tc.members, member) {
					if err != nil {
						t.Fatalf("workspace %s was not copied: %v", member, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("unexpected workspace %s: %v", member, err)
				}
			}
		})
	}
}
