// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A large directory is read only up to the bound.
func TestWorkspaceGlobReadsDirectoriesWithinTheBound(t *testing.T) {
	dir := t.TempDir()
	for index := range 300 {
		if err := os.Mkdir(filepath.Join(dir, strconv.Itoa(index)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	glob := &workspaceGlob{remaining: 10}
	if _, err := glob.readDir(dir); !errors.Is(err, errWorkspaceBound) || glob.remaining != -1 {
		t.Fatalf("error = %v, remaining = %d; want the bound, one entry past it", err, glob.remaining)
	}
	entries, err := newWorkspaceGlob(false).readDir(dir)
	if err != nil || len(entries) != 300 {
		t.Fatalf("read %d entries (error %v), want 300", len(entries), err)
	}
}

// Repeated "**" cannot make matching backtrack beyond the bound.
func TestWorkspaceMatchPathIsBounded(t *testing.T) {
	path := strings.Split(strings.Repeat("a/", 40)+"b", "/")
	pattern := append(patternSegments(strings.Repeat("**/", 5000)), "c")
	if _, err := newWorkspaceGlob(false).matchPath(pattern, path); !errors.Is(err, errWorkspaceBound) {
		t.Fatalf("error = %v, want the bound", err)
	}
	pattern = append(patternSegments(strings.Repeat("**/", 50)), "b")
	for _, test := range []struct {
		pattern, path []string
		want          bool
	}{
		{pattern, path, true},
		{[]string{"**", "c"}, path, false},
		{[]string{"**", "b"}, []string{".a", "b"}, false},
		{[]string{"a", "*"}, []string{"a", "b"}, true},
	} {
		if got, err := newWorkspaceGlob(false).matchPath(test.pattern, test.path); err != nil || got != test.want {
			t.Errorf("matchPath(%d segments, %q) = %v (error %v), want %v", len(test.pattern), test.path, got, err, test.want)
		}
	}
}
