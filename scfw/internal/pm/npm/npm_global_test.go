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
	"reflect"
	"slices"
	"strings"
	"testing"
)

func runNpmGlobalFixture(args []string) int {
	if len(args) > 0 && args[0] == "prefix" {
		fmt.Println(os.Getenv("SCFW_TEST_NPM_WORKSPACE_ROOT"))
		return 0
	}
	if len(args) > 0 && args[0] == "config" {
		if os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") == "workspace-local" {
			fmt.Println(`{"error":{"code":"ENOWORKSPACES"}}`)
			return 1
		}
		if os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") == "invalid" {
			fmt.Println(`{"error":{"code":"EINVALID"}}`)
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"prefix": os.Getenv("SCFW_TEST_NPM_GLOBAL_PREFIX"), "global": os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") == "true", "userconfig": os.Getenv("SCFW_TEST_NPM_USERCONFIG"), "globalconfig": os.Getenv("SCFW_TEST_NPM_GLOBALCONFIG")})
		return 0
	}
	heading := os.Getenv("npm_config_heading")
	if heading == "" {
		heading = "npm"
	}
	color := os.Getenv("npm_config_color") == "true"
	level := "silly"
	if configured := os.Getenv("npm_config_loglevel"); configured != "" {
		level = configured
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		switch {
		case arg == "--heading" && i+1 < len(args):
			i++
			heading = args[i]
		case strings.HasPrefix(arg, "--heading="):
			heading = strings.TrimPrefix(arg, "--heading=")
		case strings.HasPrefix(arg, "--color="):
			color = strings.TrimPrefix(arg, "--color=") == "true"
		case arg == "--loglevel" && i+1 < len(args):
			i++
			level = args[i]
		case strings.HasPrefix(arg, "--loglevel="):
			level = strings.TrimPrefix(arg, "--loglevel=")
		}
	}
	if color {
		heading = "\x1b[31m" + heading + "\x1b[0m"
	}
	emit := func(message string) {
		if level == "silly" {
			fmt.Fprintln(os.Stderr, heading+" silly "+message)
		}
	}
	if os.Getenv("SCFW_TEST_NPM_GLOBAL_DRY_ERROR") == "1" {
		fmt.Fprintln(os.Stderr, "npm error code ENOENT")
		return 254
	}
	if log := os.Getenv("SCFW_TEST_NPM_GLOBAL_LOG"); log != "" && !slices.Contains(args, "--package-lock-only") {
		fmt.Fprint(os.Stderr, log)
		globalFixtureCounts(strings.Count(log, " ADD ") + strings.Count(log, " CHANGE "))
		return 0
	}
	if os.Getenv("SCFW_TEST_NPM_GLOBAL_SELF") == "true" {
		options := map[string]string{}
		for _, option := range parseNpmOptions(args) {
			options[option.name] = option.value
		}
		if slices.Contains(args, "--package-lock-only") {
			root := options["prefix"]
			manifest, err := readNpmJSONFile(filepath.Join(root, "package.json"))
			if err != nil {
				return 1
			}
			deps, _ := manifest["dependencies"].(map[string]any)
			if deps["scfw-self-source"] != "file:"+os.Getenv("SCFW_TEST_NPM_SELF_SOURCE") {
				return 1
			}
			return writeGlobalSelfLock(root)
		}
		if options["global"] == "false" {
			return 0
		}
		emit("placeDep ROOT scfw-self-source@1.0.0 OK for:  want: file:" + os.Getenv("SCFW_TEST_NPM_SELF_SOURCE"))
		emit("placeDep node_modules/scfw-self-source react@18.3.0 OK for: scfw-self-source@1.0.0 want: 18.3.0")
		emit("ADD node_modules/scfw-self-source")
		emit("ADD node_modules/scfw-self-source/node_modules/react")
		globalFixtureCounts(2)
		return 0
	}
	if os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") == "true" && !slices.Contains(args, "--package-lock-only") {
		emit("placeDep ROOT react@18.3.0 OK for:  want: 18.3.0")
		emit("ADD node_modules/react")
		globalFixtureCounts(1)
		return 0
	}
	// Native local inspection reports no change when this exact version is
	// already installed in the selected workspace member.
	if _, err := os.Stat("node_modules/react/package.json"); err == nil && os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") != "true" {
		return 0
	}
	if os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") == "true" {
		options := map[string]string{}
		for _, option := range parseNpmOptions(args) {
			options[option.name] = option.value
		}
		cwd, _ := os.Getwd()
		if options["global"] != "false" || options["prefix"] == cwd || options["userconfig"] != os.Getenv("SCFW_TEST_NPM_USERCONFIG") || options["globalconfig"] != os.Getenv("SCFW_TEST_NPM_GLOBALCONFIG") {
			return 1
		}
	}
	if slices.Contains(args, "--package-lock-only") {
		root := "."
		if os.Getenv("SCFW_TEST_NPM_GLOBAL_CONFIG") == "true" {
			for _, option := range parseNpmOptions(args) {
				if option.name == "prefix" {
					root = option.value
				}
			}
		}
		if fixture := os.Getenv("SCFW_TEST_NPM_GLOBAL_LOCK"); fixture != "" {
			content, err := os.ReadFile(fixture)
			if err != nil || os.WriteFile(filepath.Join(root, "package-lock.json"), content, 0600) != nil {
				return 1
			}
			return 0
		}
		packages := map[string]any{"node_modules/react": map[string]any{"version": "18.3.0"}}
		if os.Getenv("SCFW_TEST_NPM_GLOBAL_DUPLICATE") == "1" {
			packages = map[string]any{}
			for _, name := range []string{"alias-one", "alias-two"} {
				packages["node_modules/"+name] = map[string]any{"name": "react", "version": "18.3.0", "resolved": "https://registry.npmjs.org/react/-/react-18.3.0.tgz"}
			}
		}
		if err := writeNpmJSONFile(filepath.Join(root, "package-lock.json"), map[string]any{"packages": packages}); err != nil {
			return 1
		}
	} else {
		fmt.Fprintln(os.Stderr, "npm silly ADD node_modules/react")
	}
	return 0
}

func TestNpmGlobalInstallIgnoresMemberInstallation(t *testing.T) {
	for _, form := range []string{"short", "equals", "environment", "prefix-cluster", "explicit-local", "heading-env", "heading-separate", "heading-equals", "heading-sentinel", "logging-preferences"} {
		t.Run(form, func(t *testing.T) {
			manager := fixtureNpm(t)
			root, snapshots := globalWorkspaceFixture(t)
			member := filepath.Join(root, "packages/member")
			for _, entry := range []struct{ directory, version string }{{root, "17.0.0"}, {member, "18.3.0"}} {
				path := filepath.Join(entry.directory, "node_modules/react/package.json")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				data := []byte(`{"name":"react","version":"` + entry.version + `"}`)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				snapshots[path] = data
			}
			t.Setenv("SCFW_TEST_NPM_WORKSPACE_ROOT", root)
			t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
			t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", t.TempDir())
			t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
			t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
			command := []string{"install", "react@18.3.0"}
			switch form {
			case "short":
				command = append(command, "-g")
			case "equals":
				command = append(command, "--global=true")
			case "environment":
				t.Setenv("npm_config_global", "true")
			case "prefix-cluster":
				command = append(command, "-gC", root)
			case "heading-env":
				t.Setenv("npm_config_heading", "corp team")
				command = append(command, "-g")
			case "heading-separate":
				command = append(command, "-g", "--heading", "corp")
			case "heading-equals":
				command = append(command, "-g", "--heading=corp")
			case "heading-sentinel":
				command = []string{"install", "-g", "--heading=corp", "--", "react@18.3.0"}
			case "logging-preferences":
				t.Setenv("npm_config_heading", "corp")
				t.Setenv("npm_config_color", "true")
				t.Setenv("npm_config_loglevel", "silent")
				command = append(command, "-g", "--color=true", "--loglevel=error")
			case "explicit-local":
				t.Setenv("npm_config_global", "true")
				t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "workspace-local")
				command = append(command, "--global=false")
			}
			original := slices.Clone(command)
			t.Chdir(member)
			targets, err := manager.ResolveInstallTargets(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if form == "explicit-local" {
				want = 0
			}
			if targets.Len() != want {
				t.Fatalf("targets=%v, want %d (local installed state must not hide a global target)", targets, want)
			}
			if !slices.Equal(command, original) {
				t.Fatal("final command changed")
			}
			for path, want := range snapshots {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("source changed: %s: %v", path, err)
				}
			}
		})
	}
}

func TestNpmGlobalDiscoveryFailureStopsResolution(t *testing.T) {
	manager := fixtureNpm(t)
	t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "invalid")
	t.Chdir(fixtureNpmProject(t))
	if _, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "react@18.3.0"}); err == nil {
		t.Fatal("native configuration failure must stop resolution")
	}
}

func writeGlobalSelfLock(root string) int {
	packages := map[string]any{
		"node_modules/scfw-self-source":                    map[string]any{"version": "1.0.0", "resolved": "file:" + os.Getenv("SCFW_TEST_NPM_SELF_SOURCE")},
		"node_modules/scfw-self-source/node_modules/react": map[string]any{"version": "18.3.0", "resolved": "https://registry.npmjs.org/react/-/react-18.3.0.tgz"},
	}
	if err := writeNpmJSONFile(filepath.Join(root, "package-lock.json"), map[string]any{"packages": packages}); err != nil {
		return 1
	}
	return 0
}

func TestNpmGlobalSelfInstallPreservesRegistryDependencies(t *testing.T) {
	manager := fixtureNpm(t)
	source := filepath.Join(t.TempDir(), "source with spaces")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "package.json"), []byte(`{"name":"scfw-self-source","version":"1.0.0","dependencies":{"react":"18.3.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
	t.Setenv("SCFW_TEST_NPM_GLOBAL_SELF", "true")
	t.Setenv("SCFW_TEST_NPM_SELF_SOURCE", source)
	t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", t.TempDir())
	t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
	t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
	t.Chdir(source)
	command := []string{"install", "-g", "--install-links"}
	original := slices.Clone(command)
	targets, err := manager.ResolveInstallTargets(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if targets.Len() != 2 {
		t.Fatalf("global self-install must inspect its source and registry dependency: %v", targets)
	}
	if !slices.Equal(command, original) {
		t.Fatal("final command changed")
	}
	if !strings.Contains(fmt.Sprint(targets), "react") {
		t.Fatal("registry target missing")
	}
}

func TestNpmGlobalPlacementTranscripts(t *testing.T) {
	data, err := os.ReadFile("testdata/global_inspection/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]struct {
		Log      string
		Roots    map[string]any
		Versions map[string]string
		Handles  []string
		Error    bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "global", "lib")
			got, err := parseNpmGlobalResolution(c.Log, base)
			if (err != nil) != c.Error {
				t.Fatalf("error=%v, want error=%t", err, c.Error)
			}
			if c.Error {
				return
			}
			for name, value := range c.Roots {
				if source, ok := value.(string); ok && strings.HasPrefix(source, "file:") {
					c.Roots[name] = "file:" + filepath.Join(base, strings.TrimPrefix(source, "file:"))
				}
			}
			if !reflect.DeepEqual(got.roots, c.Roots) || !reflect.DeepEqual(got.versions, c.Versions) || !reflect.DeepEqual(got.handles, c.Handles) {
				t.Fatalf("unexpected native resolution: %+v", got)
			}
		})
	}
}

func TestNpmGlobalMetadataMismatchFailsClosed(t *testing.T) {
	for name, log := range map[string]string{
		"missing-root":      "npm silly ADD node_modules/react\n",
		"missing-placement": "npm silly placeDep ROOT react@18.3.0 OK for:  want: 18.3.0\nnpm silly ADD node_modules/missing\n",
		"changed-version":   "npm silly placeDep ROOT react@18.2.0 OK for:  want: 18.2.0\nnpm silly ADD node_modules/react\n",
	} {
		t.Run(name, func(t *testing.T) {
			manager := fixtureNpm(t)
			t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
			t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", t.TempDir())
			t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
			t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
			t.Setenv("SCFW_TEST_NPM_GLOBAL_LOG", log)
			t.Chdir(fixtureNpmProject(t))
			if _, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "-g", "react@18.3.0"}); err == nil {
				t.Fatal("incomplete or inconsistent native metadata must fail closed")
			}
		})
	}
}

func TestNpmGlobalDryRunFailureStopsResolution(t *testing.T) {
	manager := fixtureNpm(t)
	t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
	t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", filepath.Join(t.TempDir(), "missing-prefix"))
	t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
	t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
	t.Setenv("SCFW_TEST_NPM_GLOBAL_DRY_ERROR", "1")
	t.Chdir(fixtureNpmProject(t))
	if targets, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "-g", "react@18.3.0"}); err == nil {
		t.Fatalf("failed inspection must stop before a real install can create the missing prefix: targets=%v", targets)
	}
}

func globalWorkspaceFixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/global_inspection/projects.json")
	if err != nil {
		t.Fatal(err)
	}
	var files map[string]json.RawMessage
	if err := json.Unmarshal(data, &files); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	snapshots := map[string][]byte{}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		snapshots[path] = bytes.Clone(content)
	}
	if err := os.WriteFile(filepath.Join(root, "private-source.txt"), []byte("must not copy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"member", "shared"} {
		if err := os.Symlink("../packages/"+member, filepath.Join(root, "node_modules", member)); err != nil {
			t.Fatal(err)
		}
	}
	return root, snapshots
}

func globalFixtureCounts(added int) {
	if output, ok := os.LookupEnv("SCFW_TEST_NPM_GLOBAL_STDOUT"); ok {
		fmt.Fprint(os.Stdout, output)
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]int{"added": added, "changed": 0})
}

func TestNpmGlobalActivityTranscriptMustAgree(t *testing.T) {
	for _, c := range []struct {
		name, log, output string
		wantError         bool
	}{
		{"unrecognized-heading", "corp silly ADD node_modules/react", "{\"added\":1,\"changed\":0}", true},
		{"missing-summary", "npm silly placeDep ROOT react@18.3.0 OK for:  want: 18.3.0\nnpm silly ADD node_modules/react", "", true},
		{"unaccounted-activity", "npm silly placeDep ROOT react@18.3.0 OK for:  want: 18.3.0\nnpm silly ADD node_modules/react", "{\"added\":2,\"changed\":0}", true},
		{"missing-fields", "npm verbose exit 0", "{}", true},
		{"missing-changed", "npm verbose exit 0", "{\"added\":0}", true},
		{"negative-count", "npm verbose exit 0", "{\"added\":-1,\"changed\":1}", true},
		{"invalid-count-type", "npm verbose exit 0", "{\"added\":\"0\",\"changed\":0}", true},
		{"unchanged", "npm verbose exit 0", "{\"added\":0,\"changed\":0}", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			manager := fixtureNpm(t)
			t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
			t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", t.TempDir())
			t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
			t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
			t.Setenv("SCFW_TEST_NPM_GLOBAL_LOG", c.log)
			t.Setenv("SCFW_TEST_NPM_GLOBAL_STDOUT", c.output)
			t.Chdir(fixtureNpmProject(t))
			targets, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "-g", "react@18.3.0"})
			if (err != nil) != c.wantError {
				t.Fatalf("error=%v, wantError=%t, targets=%v", err, c.wantError, targets)
			}
			if !c.wantError && targets.Len() != 0 {
				t.Fatalf("unchanged installation should have no targets: %v", targets)
			}
		})
	}
}

func TestNpmGlobalCountsPrecedeCanonicalDeduplication(t *testing.T) {
	manager := fixtureNpm(t)
	t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
	t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", t.TempDir())
	t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
	t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
	t.Setenv("SCFW_TEST_NPM_GLOBAL_DUPLICATE", "1")
	t.Setenv("SCFW_TEST_NPM_GLOBAL_LOG", "npm silly placeDep ROOT alias-one@18.3.0 OK for:  want: npm:react@18.3.0\nnpm silly placeDep ROOT alias-two@18.3.0 OK for:  want: npm:react@18.3.0\nnpm silly ADD node_modules/alias-one\nnpm silly ADD node_modules/alias-two\n")
	t.Chdir(fixtureNpmProject(t))
	targets, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "-g", "alias-one@npm:react@18.3.0", "alias-two@npm:react@18.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if targets.Len() != 1 {
		t.Fatalf("two installed handles should resolve to one canonical policy package: %v", targets)
	}
}

func TestNpmGlobalPeerLayouts(t *testing.T) {
	content, err := os.ReadFile("testdata/global_inspection/peer-layouts.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]struct {
		Log      string            `json:"log"`
		Packages map[string]any    `json:"packages"`
		Want     map[string]string `json:"want"`
		Error    bool              `json:"error"`
	}
	if err := json.Unmarshal(content, &cases); err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			manager := fixtureNpm(t)
			t.Setenv("SCFW_TEST_NPM_GLOBAL_CONFIG", "true")
			t.Setenv("SCFW_TEST_NPM_GLOBAL_PREFIX", t.TempDir())
			t.Setenv("SCFW_TEST_NPM_USERCONFIG", filepath.Join(t.TempDir(), "user config"))
			t.Setenv("SCFW_TEST_NPM_GLOBALCONFIG", filepath.Join(t.TempDir(), "global config"))
			t.Setenv("SCFW_TEST_NPM_GLOBAL_LOG", c.Log)
			lock := filepath.Join(t.TempDir(), "package-lock.json")
			if err := writeNpmJSONFile(lock, map[string]any{"packages": c.Packages}); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SCFW_TEST_NPM_GLOBAL_LOCK", lock)
			t.Chdir(fixtureNpmProject(t))
			targets, err := manager.ResolveInstallTargets(context.Background(), []string{"install", "-g", "has-peer@1.0.0"})
			if c.Error {
				if err == nil {
					t.Fatalf("expected conflicting global metadata to fail, got %v", targets)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for pkg := range targets.Items() {
				got[pkg.Name] = pkg.Version
				if pkg.Name == "is-number" && pkg.Source != "https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz" {
					t.Fatalf("registry dependency source changed: %+v", pkg)
				}
			}
			if !reflect.DeepEqual(got, c.Want) {
				t.Fatalf("targets=%v, want %v", got, c.Want)
			}
		})
	}
}
