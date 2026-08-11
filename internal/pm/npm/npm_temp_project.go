// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/scfw/scfw/internal/ecosystem"
	"github.com/DataDog/scfw/scfw/internal/pm"
)

// npmFileURIPrefix is the URI scheme npm uses for local package dependencies.
const npmFileURIPrefix = "file:"

// npmNodeModulesPrefix prefixes every installed-package entry key in
// package-lock.json's "packages" map.
const npmNodeModulesPrefix = "node_modules/"

// npmDependencySections are the dependency sections present in npm's
// package.json and package-lock.json files.
var npmDependencySections = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// npmTempProject prepares a temporary npm project that duplicates a real
// one, allowing npm install commands to be resolved safely and without
// affecting the original. Its resources exist only between
// newNpmTempProject and cleanup.
type npmTempProject struct {
	executable  string
	projectRoot string // empty if the current directory is not part of an npm project
	dir         string
}

// newNpmTempProject resolves the current npm project root (if any) and
// copies its package.json, package-lock.json, node_modules, and .npmrc
// into a fresh temporary directory. The caller must call cleanup when done.
func newNpmTempProject(ctx context.Context, executable string) (*npmTempProject, error) {
	projectRoot, err := resolveNpmProjectRoot(ctx, executable)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve npm project root: %w", err)
	}

	dir, err := os.MkdirTemp("", "scfw-npm-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary npm project directory: %w", err)
	}
	// Resolved so that later relative-path computations against projectRoot
	// (itself resolved, since it comes from `npm prefix`) reflect the real
	// filesystem structure rather than diverging across a symlinked ancestor
	// (e.g. macOS's /var -> /private/var).
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}

	proj := &npmTempProject{executable: executable, projectRoot: projectRoot, dir: dir}

	if projectRoot != "" {
		if err := proj.copyProjectFiles(); err != nil {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				slog.Warn("failed to remove temporary npm project directory", "dir", dir, "error", rmErr)
			}
			return nil, err
		}
	}

	return proj, nil
}

func (p *npmTempProject) cleanup() {
	if err := os.RemoveAll(p.dir); err != nil {
		slog.Warn("failed to remove temporary npm project directory", "dir", p.dir, "error", err)
	}
}

func (p *npmTempProject) copyProjectFiles() error {
	if err := copyNpmPackageJSON(p.projectRoot, p.dir); err != nil {
		return err
	}
	if err := copyNpmLockfile(p.projectRoot, p.dir); err != nil {
		return err
	}
	if err := copyNpmNodeModules(p.projectRoot, p.dir); err != nil {
		return err
	}
	return copyNpmrc(p.projectRoot, p.dir)
}

// resolveNpmProjectRoot runs `<executable> prefix` and returns its output if
// that directory contains a package.json, or "" if the current directory
// isn't part of an npm project.
func resolveNpmProjectRoot(ctx context.Context, executable string) (string, error) {
	output, err := exec.CommandContext(ctx, executable, "prefix").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run %q prefix: %w", executable, err)
	}

	prefix := strings.TrimSpace(string(output))
	if prefix == "" {
		return "", errors.New("npm prefix returned no output")
	}

	if _, err := os.Stat(filepath.Join(prefix, "package.json")); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(prefix); err == nil {
		prefix = resolved
	}
	return prefix, nil
}

// rewriteRelativePath re-relativizes a path (relative to projectRoot) so
// that it is instead relative to tempDir.
func rewriteRelativePath(relPath, projectRoot, tempDir string) string {
	abs := filepath.Join(projectRoot, relPath)
	rel, err := filepath.Rel(tempDir, abs)
	if err != nil {
		return relPath
	}
	return rel
}

// rewriteFileURI re-relativizes a "file:"-prefixed dependency spec or
// resolved URI so that it is instead relative to tempDir.
func rewriteFileURI(uri, projectRoot, tempDir string) string {
	rel := strings.TrimPrefix(uri, npmFileURIPrefix)
	return npmFileURIPrefix + rewriteRelativePath(rel, projectRoot, tempDir)
}

func rewriteNpmFileDependencies(deps map[string]any, projectRoot, tempDir string) {
	for name, spec := range deps {
		specStr, ok := spec.(string)
		if !ok || !strings.HasPrefix(specStr, npmFileURIPrefix) {
			continue
		}
		deps[name] = rewriteFileURI(specStr, projectRoot, tempDir)
	}
}

// copyNpmPackageJSON copies package.json into tempDir, re-relativizing any
// "file:"-prefixed local dependency specs along the way.
func copyNpmPackageJSON(projectRoot, tempDir string) error {
	src := filepath.Join(projectRoot, "package.json")
	content, err := readNpmJSONFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", src, err)
	}

	for _, section := range npmDependencySections {
		if deps, ok := content[section].(map[string]any); ok {
			rewriteNpmFileDependencies(deps, projectRoot, tempDir)
		}
	}

	return writeNpmJSONFile(filepath.Join(tempDir, "package.json"), content)
}

// copyNpmLockfile copies package-lock.json into tempDir, re-relativizing
// external link entry keys and any "file:"-prefixed or relative resolved
// paths along the way. If the lockfile's "packages" section is missing or
// malformed, the file is copied byte-for-byte instead.
func copyNpmLockfile(projectRoot, tempDir string) error {
	src := filepath.Join(projectRoot, "package-lock.json")
	content, err := readNpmJSONFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", src, err)
	}

	dst := filepath.Join(tempDir, "package-lock.json")

	packages, ok := content["packages"].(map[string]any)
	if !ok {
		return copyNpmFile(src, dst)
	}

	// External entry keys (anything other than "" or a "node_modules/..."
	// path) are paths to linked sources, relative to the original project root.
	for _, oldKey := range slices.Collect(maps.Keys(packages)) {
		if oldKey == "" || strings.HasPrefix(oldKey, npmNodeModulesPrefix) {
			continue
		}
		newKey := rewriteRelativePath(oldKey, projectRoot, tempDir)
		if newKey == oldKey {
			continue
		}
		packages[newKey] = packages[oldKey]
		delete(packages, oldKey)
	}

	for _, entryAny := range packages {
		entry, ok := entryAny.(map[string]any)
		if !ok {
			continue
		}

		if resolved, ok := entry["resolved"].(string); ok {
			switch {
			case strings.HasPrefix(resolved, npmFileURIPrefix):
				entry["resolved"] = rewriteFileURI(resolved, projectRoot, tempDir)
			case strings.HasPrefix(resolved, "./") || strings.HasPrefix(resolved, "../"):
				entry["resolved"] = rewriteRelativePath(resolved, projectRoot, tempDir)
			}
		}

		for _, section := range npmDependencySections {
			if deps, ok := entry[section].(map[string]any); ok {
				rewriteNpmFileDependencies(deps, projectRoot, tempDir)
			}
		}
	}

	return writeNpmJSONFile(dst, content)
}

// copyNpmNodeModules copies node_modules into tempDir, preserving symlinks
// without following them, then re-relativizes any relative symlinks so they
// still resolve correctly from their new location.
func copyNpmNodeModules(projectRoot, tempDir string) error {
	src := filepath.Join(projectRoot, "node_modules")
	info, err := os.Lstat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}

	dst := filepath.Join(tempDir, "node_modules")
	if err := copyNpmTreeWithSymlinks(src, dst); err != nil {
		return fmt.Errorf("failed to copy node_modules: %w", err)
	}
	if err := relativizeNpmSymlinks(src, dst); err != nil {
		return fmt.Errorf("failed to relativize node_modules symlinks: %w", err)
	}
	return nil
}

func copyNpmTreeWithSymlinks(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		switch {
		case d.Type()&fs.ModeSymlink != 0:
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, target)
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		default:
			return copyNpmFile(path, target)
		}
	})
}

// relativizeNpmSymlinks rewrites every relative symlink under tempNodeModules
// (which was copied from origNodeModules) into an absolute symlink pointing
// at the equivalent location under origNodeModules, since a relative
// symlink's target would otherwise no longer resolve correctly after the
// move.
func relativizeNpmSymlinks(origNodeModules, tempNodeModules string) error {
	return filepath.WalkDir(tempNodeModules, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if filepath.IsAbs(target) {
			return nil
		}

		rel, err := filepath.Rel(tempNodeModules, path)
		if err != nil {
			return err
		}
		origEntry := filepath.Join(origNodeModules, rel)
		absoluteTarget := filepath.Clean(filepath.Join(filepath.Dir(origEntry), target))

		if err := os.Remove(path); err != nil {
			return err
		}
		return os.Symlink(absoluteTarget, path)
	})
}

func copyNpmrc(projectRoot, tempDir string) error {
	src := filepath.Join(projectRoot, ".npmrc")
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return copyNpmFile(src, filepath.Join(tempDir, ".npmrc"))
}

func copyNpmFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func readNpmJSONFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var content map[string]any
	if err := json.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", path, err)
	}
	return content, nil
}

func writeNpmJSONFile(path string, content map[string]any) error {
	data, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to encode %s: %w", path, err)
	}
	return os.WriteFile(path, data, 0o644)
}

// resolveInstallCommandTargets resolves installation targets for an npm
// install command by dry-running it in this temporary project, scraping the
// verbose log for the packages it would add or change, then re-running it
// with --package-lock-only to safely resolve those targets' names, versions,
// and sources out of the updated lockfile.
func (p *npmTempProject) resolveInstallCommandTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	// Global installs don't touch this temporary project's node_modules, so
	// coerce them into local ones to resolve their targets here instead.
	localCommand := slices.DeleteFunc(slices.Clone(command), func(tok string) bool {
		return tok == "-g" || tok == "--global"
	})

	dryRunArgs := append(slices.Clone(localCommand), "--dry-run", "--loglevel", "silly")
	dryRunCmd := exec.CommandContext(ctx, p.executable, dryRunArgs...)
	dryRunCmd.Dir = p.dir
	var stderr bytes.Buffer
	dryRunCmd.Stderr = &stderr

	if err := dryRunCmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// The given npm install command results in error: nothing will be installed.
			return pm.NewSet[pm.Package](), nil
		}
		return nil, fmt.Errorf("failed to run npm dry-run install: %w", err)
	}

	dryRunLog := strings.Split(strings.TrimSpace(stderr.String()), "\n")

	targetHandles, err := extractNpmTargetHandles(dryRunLog, p.dir)
	if err != nil {
		return nil, err
	}
	if len(targetHandles) == 0 {
		return pm.NewSet[pm.Package](), nil
	}

	// Safely run the install command to write or update the lockfile only.
	lockOnlyArgs := append(slices.Clone(localCommand), "--package-lock-only", "--ignore-scripts")
	lockOnlyCmd := exec.CommandContext(ctx, p.executable, lockOnlyArgs...)
	lockOnlyCmd.Dir = p.dir
	if output, err := lockOnlyCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to run npm --package-lock-only install: %w: %s", err, output)
	}

	lockfilePath := filepath.Join(p.dir, "package-lock.json")
	lockfile, err := readNpmJSONFile(lockfilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("required package lockfile was not written while resolving installation targets")
		}
		return nil, err
	}
	dependencies, ok := lockfile["packages"].(map[string]any)
	if !ok {
		return nil, errors.New("malformed dependencies data in package-lock.json")
	}

	installTargets := pm.NewSet[pm.Package]()
	for _, handle := range targetHandles {
		pkg, err := resolveNpmInstallTarget(dependencies, p.dir, handle, "", nil)
		if err != nil {
			return nil, err
		}

		publishDate, err := ecosystem.ResolvePublishDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
		if err != nil {
			slog.Warn("failed to resolve package publish date", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version, "error", err)
		} else {
			pkg.PublishDate = publishDate
		}

		installTargets.Add(pkg)
	}
	return installTargets, nil
}

// extractNpmTargetHandles scrapes an npm dry-run install's verbose log for
// the lockfile "packages" keys ("target handles") it would add or change,
// then filters out entries that are local/linked dependencies already
// present at their resolved location, which npm can spuriously report as
// CHANGE when their resolved path is re-relativized for the temp project.
func extractNpmTargetHandles(dryRunLog []string, tempDir string) ([]string, error) {
	var targetHandles []string
	for _, line := range dryRunLog {
		tokens := strings.Fields(line)
		// All supported npm versions adhere to this format.
		if len(tokens) >= 4 && (tokens[1] == "sill" || tokens[1] == "silly") && (tokens[2] == "ADD" || tokens[2] == "CHANGE") {
			targetHandles = append(targetHandles, tokens[3])
		}
	}

	preInstall, err := readNpmJSONFile(filepath.Join(tempDir, "package-lock.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return targetHandles, nil
		}
		return nil, err
	}
	preInstallPackages, _ := preInstall["packages"].(map[string]any)

	filtered := make([]string, 0, len(targetHandles))
	for _, handle := range targetHandles {
		entry, _ := preInstallPackages[handle].(map[string]any)

		// Handles two disjoint lockfile representations of local dependencies:
		//  1. link: true with a bare relative resolved path (workspaces /
		//     symlink-based installs), which are not "file:"-prefixed.
		//  2. resolved starting with "file:" and no link field (copy-based
		//     installs, as in certain 9.x versions), which have no link key.
		isLocal := false
		if entry != nil {
			if link, ok := entry["link"].(bool); ok && link {
				isLocal = true
			}
			if resolved, ok := entry["resolved"].(string); ok && strings.HasPrefix(resolved, npmFileURIPrefix) {
				isLocal = true
			}
		}

		if isLocal {
			if _, err := os.Stat(filepath.Join(tempDir, handle)); err == nil {
				// Not being freshly downloaded or installed; exclude it.
				continue
			}
		}
		filtered = append(filtered, handle)
	}
	return filtered, nil
}

// resolveNpmInstallTarget resolves a lockfile "packages" entry (target
// handle) into a Package, recursing through link entries (workspace/symlink
// packages) until a version is found. targetNameOverride and
// targetSourceOverride carry the caller-resolved name/source through such
// recursion; pass "" and nil respectively for a top-level call.
func resolveNpmInstallTarget(
	dependencies map[string]any,
	tempDir, targetHandle, targetNameOverride string,
	targetSourceOverride *string,
) (pm.Package, error) {
	targetName := targetNameOverride
	if targetName == "" {
		// All supported npm versions adhere to this format.
		targetName = targetHandle
		if idx := strings.LastIndex(targetHandle, npmNodeModulesPrefix); idx >= 0 {
			targetName = targetHandle[idx+len(npmNodeModulesPrefix):]
		}
	}

	entryAny, ok := dependencies[targetHandle]
	if !ok {
		return pm.Package{}, fmt.Errorf("missing entry for installation target %s in package-lock.json", targetName)
	}
	entry, ok := entryAny.(map[string]any)
	if !ok {
		return pm.Package{}, fmt.Errorf("malformed entry for installation target %s in package-lock.json", targetName)
	}

	// For aliased packages ("alias": "npm:real@version"), npm records the
	// real package name under "name" in the lockfile entry.
	if entryName, ok := entry["name"].(string); ok && entryName != "" {
		targetName = entryName
	}

	version, _ := entry["version"].(string)
	if version == "" {
		// Parse recursively if this entry links to another.
		// All supported npm versions adhere to this format.
		link, _ := entry["link"].(bool)
		resolvedHandle, _ := entry["resolved"].(string)
		if !link || resolvedHandle == "" {
			return pm.Package{}, fmt.Errorf("missing version data for installation target %s in package-lock.json", targetName)
		}

		// Some versions of npm prefix the link target with "file:"; the
		// linked entry's key is the bare path, so normalize before lookup.
		resolvedHandle = strings.TrimPrefix(resolvedHandle, npmFileURIPrefix)

		var source *string
		if local := resolveNpmLocalSource(tempDir, resolvedHandle); local != "" {
			source = &local
		}
		return resolveNpmInstallTarget(dependencies, tempDir, resolvedHandle, targetName, source)
	}

	source := ""
	if targetSourceOverride != nil {
		source = *targetSourceOverride
	} else if resolved, ok := entry["resolved"].(string); ok {
		switch {
		case strings.HasPrefix(resolved, "http"), strings.HasPrefix(resolved, "git"):
			source = resolved
		case strings.HasPrefix(resolved, npmFileURIPrefix):
			source = resolveNpmLocalSource(tempDir, strings.TrimPrefix(resolved, npmFileURIPrefix))
		}
	}

	return pm.Package{Ecosystem: ecosystem.NPM, Name: targetName, Version: version, Source: source}, nil
}

// resolveNpmLocalSource resolves rel (relative to tempDir) to an absolute
// path. There is no guarantee the artifact still exists at that path; it
// only signals a local (vs. remote) origin to verifiers.
func resolveNpmLocalSource(tempDir, rel string) string {
	abs, err := filepath.Abs(filepath.Join(tempDir, rel))
	if err != nil {
		return ""
	}
	return abs
}
