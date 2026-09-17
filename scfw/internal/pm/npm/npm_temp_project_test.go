// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestRewriteRelativePath(t *testing.T) {
	projectRoot := "/home/user/project"
	tempDir := "/tmp/scfw-npm-abc123"

	got := rewriteRelativePath("../local-dep", projectRoot, tempDir)
	want := "../../home/user/local-dep"
	if got != want {
		t.Fatalf("rewriteRelativePath() = %q, want %q", got, want)
	}
}

func TestRewriteFileURI(t *testing.T) {
	projectRoot := "/home/user/project"
	tempDir := "/tmp/scfw-npm-abc123"

	got := rewriteFileURI("file:../local-dep", projectRoot, tempDir)
	want := "file:" + rewriteRelativePath("../local-dep", projectRoot, tempDir)
	if got != want {
		t.Fatalf("rewriteFileURI() = %q, want %q", got, want)
	}
}

func TestExtractNpmTargetHandles(t *testing.T) {
	tests := []struct {
		name           string
		dryRunLog      []string
		lockfileBefore string // "" means no pre-existing lockfile
		wantHandles    []string
	}{
		{
			name: "single ADD",
			dryRunLog: []string{
				"npm verbose title npm install left-pad",
				"npm silly ADD node_modules/left-pad",
				"added 1 package in 100ms",
			},
			wantHandles: []string{"node_modules/left-pad"},
		},
		{
			name: "CHANGE also counts",
			dryRunLog: []string{
				"npm silly CHANGE node_modules/react",
			},
			wantHandles: []string{"node_modules/react"},
		},
		{
			name: "sill abbreviation also counts",
			dryRunLog: []string{
				"npm sill ADD node_modules/react",
			},
			wantHandles: []string{"node_modules/react"},
		},
		{
			name: "scoped package name is preserved",
			dryRunLog: []string{
				"npm silly ADD node_modules/@scope/pkg",
			},
			wantHandles: []string{"node_modules/@scope/pkg"},
		},
		{
			name: "unrelated lines are ignored",
			dryRunLog: []string{
				"npm verbose cwd /tmp/foo",
				"npm silly idealTree buildDeps",
			},
			wantHandles: nil,
		},
		{
			name: "local dependency already present is excluded",
			dryRunLog: []string{
				"npm silly CHANGE node_modules/local-dep",
			},
			lockfileBefore: `{"packages":{"node_modules/local-dep":{"resolved":"file:../local-dep"}}}`,
			wantHandles:    nil,
		},
		{
			name: "linked dependency already present is excluded",
			dryRunLog: []string{
				"npm silly CHANGE node_modules/linked-dep",
			},
			lockfileBefore: `{"packages":{"node_modules/linked-dep":{"link":true,"resolved":"../linked-dep"}}}`,
			wantHandles:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()

			if tc.lockfileBefore != "" {
				if err := os.WriteFile(filepath.Join(tempDir, "package-lock.json"), []byte(tc.lockfileBefore), 0o644); err != nil {
					t.Fatalf("failed to write test lockfile: %v", err)
				}
				// The excluded-entry cases assert the local/linked target is
				// still present on disk at the temp project location, which is
				// part of the exclusion condition.
				for handle := range parseNpmLockfilePackages(t, tc.lockfileBefore) {
					if err := os.MkdirAll(filepath.Join(tempDir, handle), 0o755); err != nil {
						t.Fatalf("failed to create %s: %v", handle, err)
					}
				}
			}

			got, err := extractNpmTargetHandles(tc.dryRunLog, tempDir)
			if err != nil {
				t.Fatalf("extractNpmTargetHandles() returned unexpected error: %v", err)
			}
			if len(got) != len(tc.wantHandles) {
				t.Fatalf("extractNpmTargetHandles() = %v, want %v", got, tc.wantHandles)
			}
			for i := range got {
				if got[i] != tc.wantHandles[i] {
					t.Fatalf("extractNpmTargetHandles() = %v, want %v", got, tc.wantHandles)
				}
			}
		})
	}
}

func parseNpmLockfilePackages(t *testing.T, lockfile string) map[string]any {
	t.Helper()
	var content map[string]any
	if err := json.Unmarshal([]byte(lockfile), &content); err != nil {
		t.Fatalf("failed to parse test lockfile: %v", err)
	}
	packages, _ := content["packages"].(map[string]any)
	return packages
}

func TestResolveNpmInstallTarget(t *testing.T) {
	tempDir := t.TempDir()

	dependencies := map[string]any{
		"node_modules/left-pad": map[string]any{
			"version":  "1.3.0",
			"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
		},
		"node_modules/@scope/pkg": map[string]any{
			"version":  "1.0.0",
			"resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
		},
		"node_modules/aliased": map[string]any{
			"name":     "real-package",
			"version":  "2.0.0",
			"resolved": "https://registry.npmjs.org/real-package/-/real-package-2.0.0.tgz",
		},
		"node_modules/local-copy": map[string]any{
			"version":  "1.0.0",
			"resolved": "file:../local-copy",
		},
		"node_modules/linked-dep": map[string]any{
			"link":     true,
			"resolved": "../linked-dep",
		},
		"../linked-dep": map[string]any{
			"version": "3.0.0",
		},
	}

	tests := []struct {
		name       string
		handle     string
		wantName   string
		wantVer    string
		wantSource string
	}{
		{
			name:       "plain remote package",
			handle:     "node_modules/left-pad",
			wantName:   "left-pad",
			wantVer:    "1.3.0",
			wantSource: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
		},
		{
			name:       "scoped package name is preserved",
			handle:     "node_modules/@scope/pkg",
			wantName:   "@scope/pkg",
			wantVer:    "1.0.0",
			wantSource: "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
		},
		{
			name:       "aliased package uses lockfile name",
			handle:     "node_modules/aliased",
			wantName:   "real-package",
			wantVer:    "2.0.0",
			wantSource: "https://registry.npmjs.org/real-package/-/real-package-2.0.0.tgz",
		},
		{
			name:       "file: resolved local package",
			handle:     "node_modules/local-copy",
			wantName:   "local-copy",
			wantVer:    "1.0.0",
			wantSource: resolveNpmLocalSource(tempDir, "../local-copy"),
		},
		{
			name:       "linked entry recurses to target",
			handle:     "node_modules/linked-dep",
			wantName:   "linked-dep",
			wantVer:    "3.0.0",
			wantSource: resolveNpmLocalSource(tempDir, "../linked-dep"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveNpmInstallTarget(dependencies, tempDir, tc.handle, "", nil)
			if err != nil {
				t.Fatalf("resolveNpmInstallTarget(%q) returned unexpected error: %v", tc.handle, err)
			}
			want := pm.Package{Ecosystem: ecosystem.NPM, Name: tc.wantName, Version: tc.wantVer, Source: tc.wantSource}
			if got != want {
				t.Fatalf("resolveNpmInstallTarget(%q) = %+v, want %+v", tc.handle, got, want)
			}
		})
	}
}

func TestResolveNpmInstallTarget_Errors(t *testing.T) {
	tempDir := t.TempDir()

	dependencies := map[string]any{
		"node_modules/no-version": map[string]any{},
	}

	tests := []struct {
		name   string
		handle string
	}{
		{name: "missing entry", handle: "node_modules/missing"},
		{name: "missing version and not a link", handle: "node_modules/no-version"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveNpmInstallTarget(dependencies, tempDir, tc.handle, "", nil); err == nil {
				t.Fatalf("resolveNpmInstallTarget(%q) = nil error, want error", tc.handle)
			}
		})
	}
}

func TestCopyNpmPackageJSON_RewritesFileDependencies(t *testing.T) {
	projectRoot := t.TempDir()
	tempDir := t.TempDir()

	packageJSON := `{"name":"test","dependencies":{"local-dep":"file:../local-dep"}}`
	if err := os.WriteFile(filepath.Join(projectRoot, "package.json"), []byte(packageJSON), 0o644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	if err := copyNpmPackageJSON(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmPackageJSON() returned unexpected error: %v", err)
	}

	got, err := readNpmJSONFile(filepath.Join(tempDir, "package.json"))
	if err != nil {
		t.Fatalf("failed to read copied package.json: %v", err)
	}
	deps, ok := got["dependencies"].(map[string]any)
	if !ok {
		t.Fatalf("copied package.json missing dependencies: %+v", got)
	}
	want := rewriteFileURI("file:../local-dep", projectRoot, tempDir)
	if deps["local-dep"] != want {
		t.Fatalf("dependencies[local-dep] = %v, want %v", deps["local-dep"], want)
	}
}

func TestCopyNpmPackageJSON_NoSourceFileIsANoOp(t *testing.T) {
	projectRoot := t.TempDir()
	tempDir := t.TempDir()

	if err := copyNpmPackageJSON(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmPackageJSON() returned unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tempDir, "package.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no package.json to be written, got err = %v", err)
	}
}

func TestCopyNpmrc_CopiesExistingFile(t *testing.T) {
	projectRoot := t.TempDir()
	tempDir := t.TempDir()

	npmrc := "save-exact=true\n"
	if err := os.WriteFile(filepath.Join(projectRoot, ".npmrc"), []byte(npmrc), 0o644); err != nil {
		t.Fatalf("failed to write .npmrc: %v", err)
	}

	if err := copyNpmrc(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmrc() returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tempDir, ".npmrc"))
	if err != nil {
		t.Fatalf("failed to read copied .npmrc: %v", err)
	}
	if string(got) != npmrc {
		t.Fatalf("copied .npmrc = %q, want %q", got, npmrc)
	}
}

func TestCopyNpmrc_NoSourceFileIsANoOp(t *testing.T) {
	projectRoot := t.TempDir()
	tempDir := t.TempDir()

	if err := copyNpmrc(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmrc() returned unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tempDir, ".npmrc")); !os.IsNotExist(err) {
		t.Fatalf("expected no .npmrc to be written, got err = %v", err)
	}
}

func TestCopyNpmLockfile_RewritesLinkKeysAndResolvedPaths(t *testing.T) {
	projectRoot := t.TempDir()
	// Nested one level deeper than projectRoot so that rewriting a relative
	// link key actually changes it, rather than round-tripping to itself.
	tempDir := filepath.Join(t.TempDir(), "nested")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		t.Fatalf("failed to create nested temp dir: %v", err)
	}

	lockfile := `{
		"packages": {
			"": {},
			"../linked-dep": {"version": "1.0.0"},
			"node_modules/regular-dep": {"resolved": "https://registry.npmjs.org/regular-dep/-/regular-dep-1.0.0.tgz"},
			"node_modules/local-dep": {"resolved": "file:../local-dep"}
		}
	}`
	if err := os.WriteFile(filepath.Join(projectRoot, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	if err := copyNpmLockfile(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmLockfile() returned unexpected error: %v", err)
	}

	got, err := readNpmJSONFile(filepath.Join(tempDir, "package-lock.json"))
	if err != nil {
		t.Fatalf("failed to read copied package-lock.json: %v", err)
	}
	packages, ok := got["packages"].(map[string]any)
	if !ok {
		t.Fatalf("copied package-lock.json missing packages: %+v", got)
	}

	wantLinkedKey := rewriteRelativePath("../linked-dep", projectRoot, tempDir)
	if _, ok := packages[wantLinkedKey]; !ok {
		t.Fatalf("packages missing rewritten link key %q: %+v", wantLinkedKey, packages)
	}
	if _, ok := packages["../linked-dep"]; ok {
		t.Fatalf("packages still has un-rewritten link key: %+v", packages)
	}

	regularDep := packages["node_modules/regular-dep"].(map[string]any)
	if regularDep["resolved"] != "https://registry.npmjs.org/regular-dep/-/regular-dep-1.0.0.tgz" {
		t.Fatalf("regular remote resolved path was unexpectedly rewritten: %+v", regularDep)
	}

	localDep := packages["node_modules/local-dep"].(map[string]any)
	wantResolved := rewriteFileURI("file:../local-dep", projectRoot, tempDir)
	if localDep["resolved"] != wantResolved {
		t.Fatalf("resolved = %v, want %v", localDep["resolved"], wantResolved)
	}
}

func TestCopyNpmLockfile_MalformedPackagesCopiesRawFile(t *testing.T) {
	projectRoot := t.TempDir()
	tempDir := t.TempDir()

	lockfile := `{"packages": "not-an-object"}`
	if err := os.WriteFile(filepath.Join(projectRoot, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	if err := copyNpmLockfile(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmLockfile() returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tempDir, "package-lock.json"))
	if err != nil {
		t.Fatalf("failed to read copied package-lock.json: %v", err)
	}
	if string(got) != lockfile {
		t.Fatalf("copied package-lock.json = %s, want byte-for-byte copy %s", got, lockfile)
	}
}

func TestRelativizeNpmSymlinks(t *testing.T) {
	projectRoot := t.TempDir()
	tempDir := t.TempDir()

	origNodeModules := filepath.Join(projectRoot, "node_modules")
	linkedPkg := filepath.Join(projectRoot, "..", "linked-pkg")
	if err := os.MkdirAll(linkedPkg, 0o755); err != nil {
		t.Fatalf("failed to create linked package dir: %v", err)
	}
	if err := os.MkdirAll(origNodeModules, 0o755); err != nil {
		t.Fatalf("failed to create node_modules: %v", err)
	}
	relTarget, err := filepath.Rel(origNodeModules, linkedPkg)
	if err != nil {
		t.Fatalf("failed to compute relative target: %v", err)
	}
	if err := os.Symlink(relTarget, filepath.Join(origNodeModules, "linked-pkg")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if err := copyNpmNodeModules(projectRoot, tempDir); err != nil {
		t.Fatalf("copyNpmNodeModules() returned unexpected error: %v", err)
	}

	tempLink := filepath.Join(tempDir, "node_modules", "linked-pkg")
	newTarget, err := os.Readlink(tempLink)
	if err != nil {
		t.Fatalf("failed to read relativized symlink: %v", err)
	}
	if !filepath.IsAbs(newTarget) {
		t.Fatalf("relativized symlink target %q is not absolute", newTarget)
	}
	wantTarget, err := filepath.EvalSymlinks(linkedPkg)
	if err != nil {
		t.Fatalf("failed to resolve expected symlink target: %v", err)
	}
	gotTarget, err := filepath.EvalSymlinks(newTarget)
	if err != nil {
		t.Fatalf("relativized symlink does not resolve: %v", err)
	}
	if gotTarget != wantTarget {
		t.Fatalf("relativized symlink resolves to %q, want %q", gotTarget, wantTarget)
	}
}
