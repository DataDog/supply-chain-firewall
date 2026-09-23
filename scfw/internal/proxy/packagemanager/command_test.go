// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package packagemanager

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCommandConfiguresSupportedPackageManagers(t *testing.T) {
	binDirectory := t.TempDir()
	for _, name := range supportedNames {
		path := filepath.Join(binDirectory, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatalf("WriteFile(%s) returned error: %v", name, err)
		}
	}
	t.Setenv("PATH", binDirectory)
	t.Setenv("HTTPS_PROXY", "http://old-proxy:8080")
	t.Setenv("NODE_EXTRA_CA_CERTS", "/old/ca.pem")

	for _, name := range supportedNames {
		t.Run(name, func(t *testing.T) {
			child, err := Command(context.Background(), []string{name, "install", "react"}, "http://127.0.0.1:4321", "/tmp/scfw-ca.pem")
			if err != nil {
				t.Fatalf("Command() returned error: %v", err)
			}

			environment := environmentMap(child.Env)
			for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				if environment[key] != "http://127.0.0.1:4321" {
					t.Errorf("%s = %q, want proxy URL", key, environment[key])
				}
			}
			if environment["GIT_SSL_CAINFO"] != "/tmp/scfw-ca.pem" {
				t.Errorf("GIT_SSL_CAINFO = %q", environment["GIT_SSL_CAINFO"])
			}
			if environment["NO_PROXY"] != "" || environment["no_proxy"] != "" {
				t.Error("NO_PROXY variables were not cleared")
			}
			switch name {
			case "npm", "pnpm":
				for key, want := range map[string]string{
					"NODE_EXTRA_CA_CERTS":    "/tmp/scfw-ca.pem",
					"npm_config_cafile":      "/tmp/scfw-ca.pem",
					"npm_config_https_proxy": "http://127.0.0.1:4321",
					"npm_config_noproxy":     "",
					"npm_config_proxy":       "http://127.0.0.1:4321",
				} {
					if environment[key] != want {
						t.Errorf("%s = %q, want %q", key, environment[key], want)
					}
				}
			case "yarn":
				for key, want := range map[string]string{
					"NODE_EXTRA_CA_CERTS":     "/tmp/scfw-ca.pem",
					"YARN_HTTP_PROXY":         "http://127.0.0.1:4321",
					"YARN_HTTPS_CA_FILE_PATH": "/tmp/scfw-ca.pem",
					"YARN_HTTPS_PROXY":        "http://127.0.0.1:4321",
				} {
					if environment[key] != want {
						t.Errorf("%s = %q, want %q", key, environment[key], want)
					}
				}
			case "bun":
				if environment["NODE_EXTRA_CA_CERTS"] != "/tmp/scfw-ca.pem" {
					t.Errorf("NODE_EXTRA_CA_CERTS = %q", environment["NODE_EXTRA_CA_CERTS"])
				}
			case "pip", "pip3":
				for key, want := range map[string]string{
					"PIP_CERT":           "/tmp/scfw-ca.pem",
					"PIP_PROXY":          "http://127.0.0.1:4321",
					"REQUESTS_CA_BUNDLE": "/tmp/scfw-ca.pem",
				} {
					if environment[key] != want {
						t.Errorf("%s = %q, want %q", key, environment[key], want)
					}
				}
			case "poetry":
				if environment["REQUESTS_CA_BUNDLE"] != "/tmp/scfw-ca.pem" {
					t.Errorf("REQUESTS_CA_BUNDLE = %q", environment["REQUESTS_CA_BUNDLE"])
				}
			case "uv":
				if environment["SSL_CERT_FILE"] != "/tmp/scfw-ca.pem" {
					t.Errorf("SSL_CERT_FILE = %q", environment["SSL_CERT_FILE"])
				}
			}

			wantArgs := []string{"install", "react"}
			if name == "bun" {
				wantArgs = []string{"install", "--cafile", "/tmp/scfw-ca.pem", "react"}
			}
			if filepath.Base(child.Args[0]) != name || !slices.Equal(child.Args[1:], wantArgs) {
				t.Errorf("child.Args = %q, want executable %q and arguments %q", child.Args, name, wantArgs)
			}
		})
	}
}

func TestCommandRejectsUnsupportedPackageManager(t *testing.T) {
	_, err := Command(context.Background(), []string{"cargo", "install", "ripgrep"}, "http://127.0.0.1:4321", "/tmp/scfw-ca.pem")
	if err == nil || !strings.Contains(err.Error(), "unsupported package manager") {
		t.Fatalf("Command() error = %v, want unsupported package manager", err)
	}
}

func TestBunArgumentsOnlyChangesPackageManagerCommands(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      []string
	}{
		{
			name:      "runtime command is unchanged",
			arguments: []string{"run", "build", "--", "--verbose"},
			want:      []string{"run", "build", "--", "--verbose"},
		},
		{
			name:      "global flags before package command",
			arguments: []string{"--cwd", "/project", "install", "react"},
			want:      []string{"--cwd", "/project", "install", "--cafile", "/tmp/scfw-ca.pem", "react"},
		},
		{
			name:      "script named like package command is unchanged",
			arguments: []string{"run", "install"},
			want:      []string{"run", "install"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bunArguments(test.arguments, "/tmp/scfw-ca.pem")
			if !slices.Equal(got, test.want) {
				t.Errorf("bunArguments() = %q, want %q", got, test.want)
			}
		})
	}
}

func environmentMap(environment []string) map[string]string {
	result := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		result[key] = value
	}
	return result
}
