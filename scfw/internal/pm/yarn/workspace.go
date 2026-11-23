// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// maxWorkspaceEntries bounds the directory entries and lookups one workspace
// resolution inspects; the patterns come from the project's manifests.
var maxWorkspaceEntries = 100000

var errWorkspaceBound = errors.New("yarn workspace patterns cover more directories than SCFW inspects; run the command from the workspace directory instead")

func unsupportedWorkspacePattern(name string) error {
	return fmt.Errorf("yarn workspace %q was not found, and the workspaces patterns use brace ranges, extglobs, POSIX classes, or symlinked directories under **, which SCFW does not evaluate; run the command from the workspace directory instead", name)
}

// unsupportedGlob reports constructs the walk does not evaluate: brace ranges
// and expansions over budget, which stay unexpanded, extglobs, and POSIX
// classes.
func unsupportedGlob(expanded string) bool {
	return strings.ContainsAny(expanded, "{(") || strings.Contains(expanded, "[[:")
}

// workspaceGlob lists the directories workspace patterns select with a
// bounded walk guided by the pattern. Literal segments are looked up, so they
// compare names as the filesystem does; wildcard segments match directory
// entries case-sensitively and follow symlinks. Yarn Classic (glob 7) selects
// directories holding a package.json. Yarn 4 (fast-glob) never enters
// node_modules, .git, or .yarn, and matches literal segments after a wildcard
// case-sensitively.
type workspaceGlob struct {
	berry     bool
	remaining int
	// incomplete records a Yarn 4 "**" reaching a symlinked directory, which
	// fast-glob descends through and the walk does not.
	incomplete bool
}

func newWorkspaceGlob(berry bool) *workspaceGlob {
	return &workspaceGlob{berry: berry, remaining: maxWorkspaceEntries}
}

func (glob *workspaceGlob) charge(count int) error {
	if glob.remaining -= count; glob.remaining < 0 {
		return errWorkspaceBound
	}
	return nil
}

// directories returns the directories pattern selects below root, spelled as
// the pattern spells them: relative to root, or absolute. In Yarn Classic each
// match is a manifest in the directory, as glob returns it, so a directory
// holding both manifests matches twice.
func (glob *workspaceGlob) directories(root, pattern string) ([]string, error) {
	spelled := ""
	if strings.HasPrefix(pattern, "/") {
		spelled = "/"
	}
	var segments []string
	for segment := range strings.SplitSeq(pattern, "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	var matches []string
	return matches, glob.walk(root, spelled, segments, false, &matches)
}

// location is the directory a spelled match names.
func (glob *workspaceGlob) location(root, spelled string) string {
	if strings.HasPrefix(spelled, "/") {
		return filepath.FromSlash(spelled)
	}
	return filepath.Join(root, filepath.FromSlash(spelled))
}

func joinSpelled(spelled, segment string) string {
	if spelled == "" || strings.HasSuffix(spelled, "/") {
		return spelled + segment
	}
	return spelled + "/" + segment
}

func ignoredByBerry(name string) bool {
	return name == "node_modules" || name == ".git" || name == ".yarn"
}

func (glob *workspaceGlob) walk(root, spelled string, segments []string, wild bool, matches *[]string) error {
	if len(segments) == 0 {
		return glob.match(root, spelled, matches)
	}
	segment, rest := segments[0], segments[1:]
	switch {
	case segment == "**":
		return glob.globstar(root, spelled, rest, true, matches)
	case segment == "." || segment == "..":
		return glob.walk(root, joinSpelled(spelled, segment), rest, wild, matches)
	case glob.berry && ignoredByBerry(segment):
		return nil
	case !strings.ContainsAny(segment, "*?[") && (!glob.berry || !wild):
		next := joinSpelled(spelled, segment)
		if found, err := glob.isDirectory(glob.location(root, next)); !found || err != nil {
			return err
		}
		return glob.walk(root, next, rest, wild, matches)
	}
	entries, err := glob.readDir(glob.location(root, spelled))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !nodeproxy.MatchSegment(segment, entry.Name()) || glob.berry && ignoredByBerry(entry.Name()) {
			continue
		}
		next := joinSpelled(spelled, entry.Name())
		directory := entry.IsDir()
		if !directory && entry.Type()&fs.ModeSymlink != 0 {
			if directory, err = glob.isDirectory(glob.location(root, next)); err != nil {
				return err
			}
		}
		if directory {
			if err := glob.walk(root, next, rest, true, matches); err != nil {
				return err
			}
		}
	}
	return nil
}

// globstar matches "**": zero or more directories that do not start with a
// dot. It never enters node_modules, whose matches glob 7 ignores and Yarn 4
// skips, and, as glob 7, it ends at a symlinked directory without descending
// through it.
func (glob *workspaceGlob) globstar(root, spelled string, rest []string, top bool, matches *[]string) error {
	// fast-glob does not return the directory a trailing "**" starts from.
	if !top || !glob.berry || len(rest) > 0 {
		if err := glob.walk(root, spelled, rest, true, matches); err != nil {
			return err
		}
	}
	entries, err := glob.readDir(glob.location(root, spelled))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || glob.berry && ignoredByBerry(name) {
			continue
		}
		next := joinSpelled(spelled, name)
		switch {
		case entry.IsDir():
			err = glob.globstar(root, next, rest, false, matches)
		case entry.Type()&fs.ModeSymlink != 0:
			var directory bool
			if directory, err = glob.isDirectory(glob.location(root, next)); directory {
				glob.incomplete = glob.incomplete || glob.berry
				err = glob.walk(root, next, rest, true, matches)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (glob *workspaceGlob) match(root, spelled string, matches *[]string) error {
	if spelled == "" {
		spelled = "."
	}
	path := glob.location(root, spelled)
	if glob.berry {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			*matches = append(*matches, spelled)
		}
		return glob.charge(1)
	}
	for _, name := range classicManifests {
		info, err := os.Stat(filepath.Join(path, name))
		if err := glob.charge(1); err != nil {
			return err
		}
		if err == nil && info.Mode().IsRegular() {
			*matches = append(*matches, joinSpelled(spelled, name))
		}
	}
	return nil
}

// readDirBatch is how many entries readDir reads at a time.
const readDirBatch = 256

// readDir reads a directory's entries in batches, charging each before the
// next, so it never reads more than one entry past the bound.
func (glob *workspaceGlob) readDir(dir string) ([]fs.DirEntry, error) {
	if err := glob.charge(1); err != nil {
		return nil, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		// Both globs skip directories they cannot read.
		return nil, nil
	}
	defer func() { _ = directory.Close() }()
	var entries []fs.DirEntry
	for {
		batch, err := directory.ReadDir(min(readDirBatch, glob.remaining+1))
		if err := glob.charge(len(batch)); err != nil {
			return nil, err
		}
		entries = append(entries, batch...)
		if err != nil {
			return entries, nil
		}
	}
}

func (glob *workspaceGlob) isDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	return err == nil && info.IsDir(), glob.charge(1)
}

// patternSegments splits a pattern or a relative path for matchPath, without a
// leading "./" or empty segments.
func patternSegments(pattern string) []string {
	var segments []string
	for segment := range strings.SplitSeq(pattern, "/") {
		if segment != "" && (segment != "." || len(segments) > 0) {
			segments = append(segments, segment)
		}
	}
	return segments
}

// matchPath matches pattern segments against path segments as micromatch
// does: "**" spans any number of segments that do not start with a dot. It
// compares every pattern segment with every path segment once, charging that
// work before it starts, so repeated "**" cannot backtrack.
func (glob *workspaceGlob) matchPath(pattern, path []string) (bool, error) {
	if err := glob.charge(len(pattern) * (len(path) + 1)); err != nil {
		return false, err
	}
	// next[j] reports whether the pattern after the current segment matches path[j:].
	next := make([]bool, len(path)+1)
	next[len(path)] = true
	for index := len(pattern) - 1; index >= 0; index-- {
		current := make([]bool, len(path)+1)
		for position := len(path); position >= 0; position-- {
			if pattern[index] == "**" {
				current[position] = next[position] || position < len(path) && !strings.HasPrefix(path[position], ".") && current[position+1]
			} else {
				current[position] = position < len(path) && nodeproxy.MatchSegment(pattern[index], path[position]) && next[position+1]
			}
		}
		next = current
	}
	return next[0], nil
}

type workspaceManifest struct {
	Name       any             `json:"name"`
	Version    any             `json:"version"`
	Private    any             `json:"private"`
	Workspaces json.RawMessage `json:"workspaces"`
}

// classicManifests are the manifests Yarn Classic looks for, in order: its npm
// registry's package.json and its own registry's yarn.json.
var classicManifests = []string{"package.json", "yarn.json"}

// readWorkspaceManifest reads the first of names in dir; found is false when
// there is none, and an unreadable or malformed one is an error.
func readWorkspaceManifest(dir string, names ...string) (manifest workspaceManifest, found bool, err error) {
	for _, name := range names {
		data, err := nodeproxy.ReadConfigFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err == nil {
			err = json.Unmarshal(data, &manifest)
		}
		return manifest, true, err
	}
	return manifest, false, nil
}

// workspacePatterns reads a "workspaces" field: an array of patterns, or an
// object holding one as "packages". declared is false for anything else.
func workspacePatterns(raw json.RawMessage) (patterns []string, declared bool) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	list, declared := value.([]any)
	if object, isObject := value.(map[string]any); isObject {
		list, declared = object["packages"].([]any)
	}
	for _, item := range list {
		if pattern, ok := item.(string); ok {
			patterns = append(patterns, pattern)
		}
	}
	return patterns, declared
}

// truthy mirrors JavaScript truthiness for JSON values.
func truthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case float64:
		return typed != 0
	case string:
		return typed != ""
	}
	return true
}
