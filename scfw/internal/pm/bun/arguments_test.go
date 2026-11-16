// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseCommandInsertsCafileAfterSubcommand(t *testing.T) {
	for _, test := range []struct {
		name   string
		minor  int
		bunx   bool
		args   []string
		insert int
		kept   []string
	}{
		{name: "add", minor: 4, args: []string{"add", "x"}, insert: 1},
		{name: "alias", minor: 2, args: []string{"i"}, insert: 1},
		{name: "equals globals", minor: 4, args: []string{"--cwd=sub", "--silent", "--config=b.toml", "add", "x"}, insert: 4},
		{name: "pm subcommand", minor: 4, args: []string{"pm", "view", "x"}, insert: 2},
		{name: "ci on 1.3", minor: 3, args: []string{"ci"}, insert: 1},
		{name: "user cafile and ca removed", minor: 4, args: []string{"add", "--cafile", "a.pem", "x", "--ca=PEM", "--", "--cafile", "b"},
			insert: 1, kept: []string{"add", "x", "--", "--cafile", "b"}},
		{name: "prefix cafile and ca removed", minor: 4, args: []string{"--cafile=a.pem", "--silent", "--ca=PEM", "add", "x"},
			insert: 2, kept: []string{"--silent", "add", "x"}},
		{name: "prefix cafile kept for env-only command", minor: 4, args: []string{"--cafile=a.pem", "run", "s"}, insert: -1},
		{name: "x on 1.4 stops at the package", minor: 4, args: []string{"x", "--cafile=a.pem", "pkg", "--cafile", "y", "--ca=z"},
			insert: 1, kept: []string{"x", "pkg", "--cafile", "y", "--ca=z"}},
		{name: "bunx on 1.4", minor: 4, bunx: true, args: []string{"--ca", "PEM", "pkg", "--cafile=y"}, insert: 0, kept: []string{"pkg", "--cafile=y"}},
		{name: "x on 1.4 skips option values", minor: 4,
			args:   []string{"x", "-p", "pkg", "--cwd", "sub", "--env-file", "e", "--minimum-release-age", "5", "--cafile", "a.pem", "--ca=PEM", "bin", "--cafile=y"},
			insert: 1, kept: []string{"x", "-p", "pkg", "--cwd", "sub", "--env-file", "e", "--minimum-release-age", "5", "bin", "--cafile=y"}},
		{name: "bunx on 1.4 skips option values", minor: 4, bunx: true, args: []string{"--package", "pkg", "--cafile=a.pem", "bin"},
			insert: 0, kept: []string{"--package", "pkg", "bin"}},
		{name: "bunx on 1.3", minor: 3, bunx: true, args: []string{"pkg"}, insert: -1},
		{name: "registry kept", minor: 4, args: []string{"add", "--registry", "https://r.example/", "x"}, insert: 1},
		{name: "ci script on 1.2", minor: 2, args: []string{"ci"}, insert: -1},
		{name: "space-form global runs a script", minor: 4, args: []string{"--cwd", "sub", "add"}, insert: -1},
		{name: "pm without subcommand", minor: 4, args: []string{"pm", "--help"}, insert: -1},
		{name: "run", minor: 4, args: []string{"run", "build", "--", "--cafile", "y"}, insert: -1},
		{name: "x on 1.3", minor: 3, args: []string{"x", "pkg", "--cafile", "y"}, insert: -1},
		{name: "create", minor: 4, args: []string{"create", "tpl"}, insert: -1},
		{name: "file", minor: 4, args: []string{"file.ts"}, insert: -1},
		{name: "eval", minor: 4, args: []string{"-e", "code"}, insert: -1},
		{name: "separator first", minor: 4, args: []string{"--", "add"}, insert: -1},
		{name: "bare", minor: 4, args: nil, insert: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseCommand(test.minor, test.bunx, test.args)
			kept := test.kept
			if kept == nil {
				kept = test.args
			}
			if parsed.insert != test.insert || !slices.Equal(parsed.args, kept) {
				t.Fatalf("insert=%d args=%q, want %d %q", parsed.insert, parsed.args, test.insert, kept)
			}
		})
	}
	for _, args := range [][]string{{"x", "--cwd=sub", "--cafile=ca.pem", "pkg"}, {"x", "--cafile=ca.pem", "--cwd", "sub", "pkg"}} {
		if parsed := parseCommand(4, false, args); parsed.cwd != "sub" || !slices.Equal(parsed.cafiles, []string{"ca.pem"}) {
			t.Fatalf("%q: cwd=%q cafiles=%q", args, parsed.cwd, parsed.cafiles)
		}
	}
	if parsed := parseCommand(4, true, []string{"--cwd=sub", "pkg"}); parsed.cwd != "sub" {
		t.Fatalf("bunx cwd = %q", parsed.cwd)
	}
	// Bun composes repeated --cwd values; an absolute one replaces the rest.
	for args, want := range map[string]string{
		"x --cwd a --cwd b pkg":    filepath.Join("a", "b"),
		"--cwd=a x --cwd=b pkg":    filepath.Join("a", "b"),
		"x --cwd a --cwd=/abs pkg": "/abs",
		"--cwd=a --cwd=b add pkg":  filepath.Join("a", "b"),
	} {
		if parsed := parseCommand(4, false, strings.Fields(args)); parsed.cwd != want {
			t.Errorf("%s: cwd = %q, want %q", args, parsed.cwd, want)
		}
	}
	// Values of bunx options are never read as options.
	parsed := parseCommand(4, true, []string{"--env-file", "--cwd=decoy", "--cwd", "-project", "--package", "--config=x.toml", "pkg"})
	if parsed.cwd != "-project" || parsed.config != "" || parsed.insert != 0 {
		t.Fatalf("bunx decoys: %+v", parsed)
	}
	// Bun uses the last --cafile, else the last --ca.
	for args, want := range map[string][2]string{
		"add --cafile=a --cafile=b x": {"b", ""},
		"add --ca=P --cafile=a x":     {"a", ""},
		"add --ca=P --ca=Q x":         {"", "Q"},
	} {
		cafiles, cas := parseCommand(4, false, strings.Fields(args)).effectiveCA()
		if strings.Join(cafiles, "") != want[0] || strings.Join(cas, "") != want[1] {
			t.Errorf("%s: cafiles=%q cas=%q, want %q", args, cafiles, cas, want)
		}
	}
	parsed = parseCommand(4, false, []string{"--cafile=p.pem", "--cwd=sub", "-c=b.toml", "add", "--cafile=a.pem", "--ca", "PEM", "--registry=https://r.example/"})
	if parsed.cwd != "sub" || parsed.config != "b.toml" || !slices.Equal(parsed.cafiles, []string{"p.pem", "a.pem"}) ||
		!slices.Equal(parsed.cas, []string{"PEM"}) || !slices.Equal(parsed.registries, []string{"https://r.example/"}) {
		t.Fatalf("parsed = %+v", parsed)
	}
}
