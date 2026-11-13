// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"slices"
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
		{name: "prefix cafile kept for env-only command", minor: 4, args: []string{"--cafile=a.pem", "x", "pkg"}, insert: -1},
		{name: "registry kept", minor: 4, args: []string{"add", "--registry", "https://r.example/", "x"}, insert: 1},
		{name: "ci script on 1.2", minor: 2, args: []string{"ci"}, insert: -1},
		{name: "space-form global runs a script", minor: 4, args: []string{"--cwd", "sub", "add"}, insert: -1},
		{name: "pm without subcommand", minor: 4, args: []string{"pm", "--help"}, insert: -1},
		{name: "run", minor: 4, args: []string{"run", "build", "--", "--cafile", "y"}, insert: -1},
		{name: "x", minor: 4, args: []string{"x", "pkg", "--cafile", "y"}, insert: -1},
		{name: "bunx", minor: 4, bunx: true, args: []string{"add"}, insert: -1},
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
	parsed := parseCommand(4, false, []string{"--cafile=p.pem", "--cwd=sub", "-c=b.toml", "add", "--cafile=a.pem", "--ca", "PEM", "--registry=https://r.example/"})
	if parsed.cwd != "sub" || parsed.config != "b.toml" || !slices.Equal(parsed.cafiles, []string{"p.pem", "a.pem"}) ||
		!slices.Equal(parsed.cas, []string{"PEM"}) || !slices.Equal(parsed.registries, []string{"https://r.example/"}) {
		t.Fatalf("parsed = %+v", parsed)
	}
}
