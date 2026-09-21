// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestProxyCommandValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "missing separator", args: []string{"npm", "install"}, wantErr: "missing"},
		{name: "argument before separator", args: []string{"unexpected", "--", "npm", "install"}, wantErr: "unexpected"},
		{name: "missing command", args: []string{"--"}, wantErr: "no command"},
		{name: "unsupported command", args: []string{"--", "twine", "upload"}, wantErr: "supported package managers"},
		{name: "explicit zero status", args: []string{"--http-status", "0", "--", "npm", "install"}, wantErr: "between 200 and 599"},
		{name: "status below final response range", args: []string{"--http-status", "199", "--", "npm", "install"}, wantErr: "between 200 and 599"},
		{name: "status above response range", args: []string{"--http-status=600", "--", "npm", "install"}, wantErr: "between 200 and 599"},
		{name: "npm accepted", args: []string{"--", "npm", "install"}},
		{name: "synthetic status accepted", args: []string{"--http-status", "503", "--", "npm", "install"}},
		{name: "npm path accepted", args: []string{"--", "/usr/local/bin/npm", "install"}},
		{name: "all managers accepted", args: []string{"--", "uv", "sync"}},
		{name: "pip accepted", args: []string{"--", "pip", "install", "requests"}},
		{name: "publish rejected", args: []string{"--", "npm", "publish"}, wantErr: "install-only"},
		{name: "twine rejected", args: []string{"--", "twine", "upload"}, wantErr: "supported package managers"},
		{name: "index override rejected", args: []string{"--", "pip", "install", "--index-url", "https://example", "requests"}, wantErr: "registry option"},
		{name: "short index override rejected", args: []string{"--", "pip", "install", "-i", "https://example", "requests"}, wantErr: "registry option"},
		{name: "npm run bypass rejected", args: []string{"--", "npm", "run", "install"}, wantErr: "not an installation"},
		{name: "uv run bypass rejected", args: []string{"--", "uv", "run", "pip", "install", "requests"}, wantErr: "not an installation"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "proxy -- npm <args...>", Args: validateProxyArgs, Run: func(_ *cobra.Command, _ []string) {}}
			command.Flags().Int("http-status", 0, "")
			command.SetArgs(test.args)
			command.SilenceErrors = true
			command.SilenceUsage = true
			err := command.Execute()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Execute(%v) returned unexpected error: %v", test.args, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Execute(%v) error = %v, want it to contain %q", test.args, err, test.wantErr)
			}
		})
	}
}
