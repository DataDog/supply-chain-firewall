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
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

type npmGlobalProject struct{ prefix string }

type npmGlobalResolution struct {
	roots      map[string]any
	versions   map[string]string
	handles    []string
	placements map[string]npmGlobalDependency
}

type npmGlobalDependency struct {
	owner, wanted string
}

var npmGlobalPlacement = regexp.MustCompile(`^npm (?:sill|silly) placeDep (\S+) (\S+) OK for: (.*?) want: (.+)$`)

// Global dry runs retain npm's original cwd and destination. In particular,
// npm synthesizes a current-directory package when no positional target remains.
// Dry-run and ignore-scripts prevent project/destination writes; only npm's
// ordinary cache and log files may be written. Local installed state is irrelevant.
func (p *npmTempProject) resolveGlobalInstallTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], error) {
	args := npmInspectionArgs(command, "--dry-run", "--ignore-scripts", "--loglevel=silly", "--heading=npm", "--color=false", "--json")
	child := exec.CommandContext(ctx, p.executable, args...)
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	if err := child.Run(); err != nil {
		// A dry run may fail before npm creates a fresh global prefix even
		// though the real install would succeed. Inspection failure must never
		// become an empty/allowed target set.
		return nil, fmt.Errorf("failed to run global npm dry-run install: %w", err)
	}
	base := p.global.prefix
	if runtime.GOOS != "windows" {
		base = filepath.Join(base, "lib")
	}
	resolution, err := parseNpmGlobalResolution(stderr.String(), base)
	if err != nil {
		return nil, err
	}
	count, err := npmGlobalTargetCount(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	if count != len(resolution.handles) {
		return nil, fmt.Errorf("npm global dry run reported %d targets but its log identified %d", count, len(resolution.handles))
	}
	targets := pm.NewSet[pm.Package]()
	if len(resolution.handles) == 0 {
		return targets, nil
	}
	if len(resolution.roots) == 0 {
		return nil, errors.New("npm global dry run returned targets without root package requests")
	}
	// Only native root requests belong in this private project. Copying the
	// caller's manifest would add unrelated dependencies to explicit global installs.
	manifest := map[string]any{"name": "scfw-global-inspection", "version": "0.0.0", "private": true, "dependencies": resolution.roots}
	if err := writeNpmJSONFile(filepath.Join(p.dir, "package.json"), manifest); err != nil {
		return nil, err
	}
	// Keep original relative operands anchored to the caller's cwd. All writes
	// are forced into the private prefix. Peer placement can differ between
	// global and shallow layouts; reconcile those targets by their dependency edges.
	args = npmInspectionArgs(command, p.inspectionOptions...)
	args = npmInspectionArgs(args, "--global=false", "--global-style=true", "--install-strategy=shallow", "--package-lock-only", "--package-lock=true", "--ignore-scripts", "--save")
	child = exec.CommandContext(ctx, p.executable, args...)
	if output, err := child.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to resolve global npm lockfile: %w: %s", err, output)
	}
	lock, err := readNpmJSONFile(filepath.Join(p.dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	dependencies, ok := lock["packages"].(map[string]any)
	if !ok {
		return nil, errors.New("malformed global inspection package lockfile")
	}
	for _, handle := range resolution.handles {
		pkg, err := resolveNpmGlobalInstallTarget(dependencies, p.dir, handle, resolution)
		if err != nil {
			return nil, err
		}
		if version, ok := resolution.versions[handle]; !ok || version != pkg.Version {
			return nil, fmt.Errorf("npm global target %s disagrees with inspection lockfile", handle)
		}
		// Equal alias versions can denote different packages after npm moves
		// peers between the global and shallow layouts. Check native alias
		// identity even when the original handle exists in the private lock.
		if name, alias := strings.CutPrefix(resolution.placements[handle].wanted, "npm:"); alias {
			if version := strings.LastIndex(name, "@"); version > 0 {
				name = name[:version]
			}
			if pkg.Name != name {
				return nil, fmt.Errorf("npm global target %s resolves alias for %s as different package %s", handle, name, pkg.Name)
			}
		}
		publishDate, err := p.resolvePublishDate(ctx, pkg)
		if err != nil {
			slog.Warn("failed to resolve package publish date", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version, "error", err)
		} else {
			pkg.PublishDate = publishDate
		}
		targets.Add(pkg)
	}
	return targets, nil
}

// The same native placement log supplies request specs and concrete versions.
// Lockfile metadata still owns package identity (including aliases) and source.
// Unknown or inconsistent records fail closed instead of dropping targets.
func parseNpmGlobalResolution(log, base string) (npmGlobalResolution, error) {
	result := npmGlobalResolution{roots: map[string]any{}, versions: map[string]string{}, placements: map[string]npmGlobalDependency{}}
	for _, line := range strings.Split(log, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "npm" || (fields[1] != "sill" && fields[1] != "silly") {
			continue
		}
		switch fields[2] {
		case "placeDep":
			match := npmGlobalPlacement.FindStringSubmatch(line)
			if match == nil {
				return result, fmt.Errorf("unrecognized npm global placement: %s", line)
			}
			parent, pair, owner, wanted := match[1], match[2], match[3], match[4]
			split := strings.LastIndex(pair, "@")
			if split <= 0 || split == len(pair)-1 {
				return result, errors.New("npm global placement lacks name or version")
			}
			name, version := pair[:split], pair[split+1:]
			handle := npmNodeModulesPrefix + name
			if parent != "ROOT" {
				handle = parent + "/" + handle
			}
			if !validNpmGlobalHandle(handle) {
				return result, fmt.Errorf("invalid npm global target handle %q", handle)
			}
			result.versions[handle] = version
			result.placements[handle] = npmGlobalDependency{owner: owner, wanted: wanted}
			if parent == "ROOT" {
				if strings.HasPrefix(wanted, npmFileURIPrefix) {
					source := strings.TrimPrefix(wanted, npmFileURIPrefix)
					if !filepath.IsAbs(source) {
						source = filepath.Join(base, filepath.FromSlash(source))
					}
					wanted = npmFileURIPrefix + source
				}
				result.roots[name] = wanted
			}
		case "ADD", "CHANGE":
			if len(fields) != 4 || !validNpmGlobalHandle(fields[3]) {
				return result, fmt.Errorf("invalid npm global target record: %s", line)
			}
			result.handles = append(result.handles, fields[3])
		}
	}
	return result, nil
}

// Resolve an exact handle first. When native global peer placement differs,
// follow the recorded owner's dependency edge in the private lock instead of
// guessing from a package name. Every matching owner must agree on identity,
// version and source; an existing conflicting handle remains an error.
func resolveNpmGlobalInstallTarget(dependencies map[string]any, directory, handle string, resolution npmGlobalResolution) (pm.Package, error) {
	if _, exists := dependencies[handle]; exists {
		return resolveNpmInstallTarget(dependencies, directory, handle, "", nil)
	}
	placement := resolution.placements[handle]
	name := handle[strings.LastIndex(handle, npmNodeModulesPrefix)+len(npmNodeModulesPrefix):]
	var result pm.Package
	found := false
	for ownerHandle, value := range dependencies {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		ownerName, _ := entry["name"].(string)
		if ownerName == "" {
			ownerName = ownerHandle
			if index := strings.LastIndex(ownerHandle, npmNodeModulesPrefix); index >= 0 {
				ownerName = ownerHandle[index+len(npmNodeModulesPrefix):]
			}
		}
		ownerVersion, _ := entry["version"].(string)
		if placement.owner == "" || ownerName+"@"+ownerVersion != placement.owner {
			continue
		}
		declared := false
		for _, section := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
			edges, _ := entry[section].(map[string]any)
			if spec, ok := edges[name].(string); ok && spec == placement.wanted {
				declared = true
			}
		}
		if !declared {
			continue
		}
		candidate, ok := npmGlobalDependencyHandle(dependencies, ownerHandle, name)
		if !ok {
			return pm.Package{}, fmt.Errorf("missing global dependency %s of %s", name, placement.owner)
		}
		pkg, err := resolveNpmInstallTarget(dependencies, directory, candidate, "", nil)
		if err != nil {
			return pm.Package{}, err
		}
		if pkg.Version != resolution.versions[handle] || (found && pkg != result) {
			return pm.Package{}, fmt.Errorf("npm global target %s has conflicting inspection metadata", handle)
		}
		result, found = pkg, true
	}
	if !found {
		return pm.Package{}, fmt.Errorf("missing matching dependency edge for npm global target %s", handle)
	}
	return result, nil
}

// npm resolves a dependency from the nearest node_modules directory, including
// an ancestor's hoisted peer. Never search past an existing conflicting entry.
func npmGlobalDependencyHandle(dependencies map[string]any, owner, name string) (string, bool) {
	for {
		handle := npmNodeModulesPrefix + name
		if owner != "" {
			handle = owner + "/" + handle
		}
		if _, exists := dependencies[handle]; exists {
			return handle, true
		}
		if owner == "" {
			return "", false
		}
		if parent := strings.LastIndex(owner, "/"+npmNodeModulesPrefix); parent >= 0 {
			owner = owner[:parent]
		} else {
			owner = ""
		}
	}
}

func validNpmGlobalHandle(handle string) bool {
	if !strings.HasPrefix(handle, npmNodeModulesPrefix) || strings.ContainsAny(handle, `\ `) {
		return false
	}
	for _, part := range strings.Split(handle, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// npm 7 prints a JSON summary; newer npm can prefix it with dry-run action
// lines. Reconcile the native activity count so an unknown log format cannot
// silently turn a pending installation into an allowed empty target set.
func npmGlobalTargetCount(output []byte) (int, error) {
	output = bytes.TrimSpace(output)
	if start := bytes.LastIndex(output, []byte("\n{")); start >= 0 {
		output = output[start+1:]
	}
	var summary struct {
		Added   *int `json:"added"`
		Changed *int `json:"changed"`
	}
	if err := json.Unmarshal(output, &summary); err != nil {
		return 0, fmt.Errorf("failed to decode npm global dry-run summary: %w", err)
	}
	if summary.Added == nil || summary.Changed == nil || *summary.Added < 0 || *summary.Changed < 0 {
		return 0, errors.New("npm global dry-run summary lacks valid activity counts")
	}
	return *summary.Added + *summary.Changed, nil
}
