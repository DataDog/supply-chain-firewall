// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Model npm's CLI prefix overriding Cmd.Dir, including inspection writes.
func runNpmPrefixFixture(args []string) int {
	directory, _ := os.Getwd()
	options := map[string]string{}
	// Model native aliases independently from the production option parser.
	parsedArgs := slices.Clone(args)
	for i, arg := range parsedArgs {
		name, value, equal := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.HasPrefix(arg, "-") && (name == "prefi" || name == "prefix" || name == "C" || name == "sC" || name == "qC" || name == "dC" || name == "gC") {
			parsedArgs[i] = "--prefix"
			if equal {
				parsedArgs[i] += "=" + value
			}
		}
	}
	for _, option := range parseNpmOptions(parsedArgs) {
		options[option.name] = option.value
	}
	if prefix := options["prefix"]; prefix != "" {
		directory = prefix
	}
	if len(args) > 0 && args[0] == "prefix" {
		fmt.Println(directory)
		return 0
	}
	if len(args) > 0 && args[0] == "config" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"userconfig": os.Getenv("SCFW_TEST_NPM_USERCONFIG"), "globalconfig": os.Getenv("SCFW_TEST_NPM_GLOBALCONFIG"), "omit": []string{}, "include": []string{}})
		return 0
	}
	data, err := os.ReadFile(filepath.Join(directory, ".npmrc"))
	if err != nil || string(data) != "# selected project\n" {
		return 1
	}
	if directory != os.Getenv("SCFW_TEST_NPM_PREFIX_PROJECT") {
		if options["userconfig"] != os.Getenv("SCFW_TEST_NPM_USERCONFIG") || options["globalconfig"] != os.Getenv("SCFW_TEST_NPM_GLOBALCONFIG") {
			return 1
		}
	}
	beforeSentinel := args
	if index := slices.Index(args, "--"); index >= 0 {
		beforeSentinel = args[:index]
	}
	if slices.Contains(beforeSentinel, "--dry-run") {
		fmt.Fprintln(os.Stderr, "npm silly ADD node_modules/react")
		return 0
	}
	if !slices.Contains(beforeSentinel, "--package-lock-only") || !slices.Contains(beforeSentinel, "--save") {
		return 1
	}
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"name":"inspection-write"}`), 0600); err != nil {
		return 1
	}
	if err := writeNpmJSONFile(filepath.Join(directory, "package-lock.json"), map[string]any{"packages": map[string]any{"node_modules/react": map[string]any{"version": "18.3.0", "resolved": "https://registry.npmjs.org/react/-/react-18.3.0.tgz"}}}); err != nil {
		return 1
	}
	return 0
}

func TestNpmResolveInstallTargetsPrefixIsolation(t *testing.T) {
	for _, form := range []string{"separate", "equals", "short", "short-equals", "abbreviated", "single-dash", "cluster", "cluster-equals", "global-cluster", "before-command", "sentinel"} {
		t.Run(form, func(t *testing.T) {
			manager := fixtureNpm(t)
			project := filepath.Join(t.TempDir(), "selected project with spaces")
			if err := os.Mkdir(project, 0700); err != nil {
				t.Fatal(err)
			}
			original := []byte(`{"name":"selected-project","version":"1.0.0"}`)
			if err := os.WriteFile(filepath.Join(project, "package.json"), original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, ".npmrc"), []byte("# selected project\n"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SCFW_TEST_NPM_PREFIX_PROJECT", project)
			t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
			t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
			t.Chdir(fixtureNpmProject(t))
			command := []string{"install", "react@18.3.0", "--no-save"}
			switch form {
			case "separate":
				command = append(command, "--prefix", project)
			case "equals":
				command = append(command, "--prefix="+project)
			case "short":
				command = append(command, "-C", project)
			case "short-equals":
				command = append(command, "-C="+project)
			case "abbreviated":
				command = append(command, "--prefi", project)
			case "single-dash":
				command = append(command, "-prefix", project)
			case "cluster":
				command = append(command, "-sC", project)
			case "cluster-equals":
				command = append(command, "-qC="+project)
			case "global-cluster":
				command = append(command, "-gC", project)
			case "before-command":
				command = append([]string{"--prefix", project}, command...)
			case "sentinel":
				command = []string{"install", "--prefix", project, "--no-save", "--", "react@18.3.0"}
			}
			beforeArgs := slices.Clone(command)
			targets, resolveErr := manager.ResolveInstallTargets(context.Background(), command)
			after, err := os.ReadFile(filepath.Join(project, "package.json"))
			if err != nil || !bytes.Equal(after, original) {
				t.Errorf("resolver changed selected project manifest: %s (%v)", after, err)
			}
			if _, err := os.Stat(filepath.Join(project, "package-lock.json")); !os.IsNotExist(err) {
				t.Errorf("resolver wrote selected project lockfile: %v", err)
			}
			if !slices.Equal(command, beforeArgs) {
				t.Error("resolver modified original command")
			}
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if targets.Len() != 1 {
				t.Fatalf("targets = %v, want selected project dependency", targets)
			}
		})
	}
}
