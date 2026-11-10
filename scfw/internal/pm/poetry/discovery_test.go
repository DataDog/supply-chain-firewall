// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestPoetryOwnArgumentBoundary(t *testing.T) {
	for _, test := range []struct{ command, own []string }{
		{[]string{"run", "python", "-Cchild", "--project", "child"}, []string{"run"}},
		{[]string{"-C", "run", "install"}, []string{"-C", "run", "install"}},
		{[]string{"--project", "run", "run", "--directory=project", "python", "-Pchild"}, []string{"--project", "run", "run", "--directory=project"}},
		{[]string{"run", "-C", "project", "--", "python", "-Cchild"}, []string{"run", "-C", "project"}},
		{[]string{"add", "--", "git+https://git.example/repo"}, []string{"add", "--", "git+https://git.example/repo"}},
	} {
		before := slices.Clone(test.command)
		if own := poetryOwnArguments(test.command); !slices.Equal(own, test.own) {
			t.Errorf("%v: own=%v, want %v", test.command, own, test.own)
		}
		if !slices.Equal(before, test.command) {
			t.Fatal("discovery mutated command")
		}
	}
}

func TestPoetryDiscoveryIgnoresRunChildOptions(t *testing.T) {
	root := isolatedPoetryProject(t)
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	poetrySettingsFixture(t, "invalid.lock", filepath.Join(child, "pyproject.toml"))
	t.Chdir(root)
	command := []string{"run", "python", "child-options.py", "-P", "child", "--project=child", "-Cchild", "--directory", "child"}
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	directory, err := manager.ProjectDirectory(command)
	if err != nil || directory != root {
		t.Fatalf("child selected working directory: %q / %v", directory, err)
	}
	settings, err := readPoetrySettings(command)
	if err != nil || settings.projectDirectory != root {
		t.Fatalf("child selected project: %q / %v", settings.projectDirectory, err)
	}
	if _, err := manager.ProxyOptions(command); err != nil {
		t.Fatal(err)
	}
	options, err := manager.PyPIClassifierOptions(command)
	if err != nil || !slices.Equal(options.SimpleIndexURLs, []string{"https://index.example/simple/"}) {
		t.Fatalf("child altered source hints: %v / %v", options, err)
	}
	spec, err := manager.ProxyCommand(context.Background(), command, poetryInvocationConfig(t))
	if err != nil || !slices.Equal(spec.Args, command) {
		t.Fatalf("child arguments changed: %v / %v", spec.Args, err)
	}
}

func TestPoetryCertificateEnvironmentNamesUseFullUppercase(t *testing.T) {
	for name, expected := range map[string]string{"foo-bar": "FOO_BAR", "straße": "STRASSE", "ﬀ": "FF"} {
		if prefix := poetryCertificatePrefix(name); prefix != "POETRY_CERTIFICATES_"+expected+"_" {
			t.Fatalf("Python environment name changed: %q", prefix)
		}
		t.Setenv("POETRY_CERTIFICATES_"+expected+"_CERT", "custom.pem")
		if value := (poetrySettings{}).get("certificates", name, "cert"); value != "custom.pem" {
			t.Fatalf("certificate override was lost for %q: %v", name, value)
		}
	}
}
