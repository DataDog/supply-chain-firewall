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
	"testing"
)

type npmSelectionFixture struct {
	Command         []string          `json:"command"`
	Environment     map[string]string `json:"environment"`
	ProjectConfig   string            `json:"project_config"`
	Configuration   json.RawMessage   `json:"configuration"`
	Packages        map[string]any    `json:"packages"`
	InitialPackages map[string]any    `json:"initial_packages"`
	Expected        []string          `json:"expected"`
}

func readNpmSelectionFixtures(directory string) (map[string]npmSelectionFixture, error) {
	data, err := os.ReadFile(filepath.Join(directory, "production-selection", "responses.json"))
	if err != nil {
		return nil, err
	}
	var cases map[string]npmSelectionFixture
	err = json.Unmarshal(data, &cases)
	return cases, err
}
func runNpmSelectionFixture(directory, selected string, args []string) int {
	cases, err := readNpmSelectionFixtures(directory)
	if err != nil {
		return 1
	}
	c := cases[selected]
	if len(args) > 0 && args[0] == "prefix" {
		wd, err := os.Getwd()
		if err != nil {
			return 1
		}
		fmt.Println(wd)
		return 0
	}
	if len(args) > 0 && args[0] == "config" {
		if len(args) < 3 || !slices.Equal(args[2:len(args)-1], c.Command) {
			return 1
		}
		for key, value := range c.Environment {
			if os.Getenv(key) != value {
				return 1
			}
		}
		if c.ProjectConfig != "" {
			data, err := os.ReadFile(".npmrc")
			if err != nil || string(data) != c.ProjectConfig {
				return 1
			}
		}
		fmt.Println(string(c.Configuration))
		return 0
	}
	if slices.Contains(args, "--package-lock-only") {
		if slices.Contains(args, "--no-save") && !slices.Contains(args, "--save") {
			return 0
		}
		if err := writeNpmJSONFile("package-lock.json", map[string]any{"packages": c.Packages}); err != nil {
			return 1
		}
	} else {
		for handle := range c.Packages {
			fmt.Fprintln(os.Stderr, "npm silly ADD "+handle)
		}
	}
	return 0
}

func TestNpmResolveInstallTargetsProductionSelection(t *testing.T) {
	fixtureDir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := readNpmSelectionFixtures(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			manager := fixtureNpm(t)
			t.Setenv("SCFW_TEST_NPM_SELECTION_CASE", name)
			for key, value := range c.Environment {
				t.Setenv(key, value)
			}
			project := fixtureNpmProject(t)
			if c.ProjectConfig != "" {
				if err := os.WriteFile(filepath.Join(project, ".npmrc"), []byte(c.ProjectConfig), 0600); err != nil {
					t.Fatal(err)
				}
			}
			lockPath := filepath.Join(project, "package-lock.json")
			if c.InitialPackages != nil {
				if err := writeNpmJSONFile(lockPath, map[string]any{"packages": c.InitialPackages}); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(lockPath)
			t.Chdir(project)
			targets, err := manager.ResolveInstallTargets(context.Background(), c.Command)
			if err != nil {
				t.Fatal(err)
			}
			actual := []string{}
			for pkg := range targets.Items() {
				actual = append(actual, pkg.Name)
			}
			slices.Sort(actual)
			want := slices.Clone(c.Expected)
			slices.Sort(want)
			if !slices.Equal(actual, want) {
				t.Fatalf("selected targets = %v, want %v", actual, want)
			}
			after, err := os.ReadFile(lockPath)
			if c.InitialPackages == nil && !os.IsNotExist(err) || c.InitialPackages != nil && (err != nil || !bytes.Equal(before, after)) {
				t.Fatal("resolver modified original lockfile")
			}
		})
	}
}
