// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// isolateYarnEnvironment removes the host's Yarn, npm, proxy, and trust
// settings and enters <root>/parent/project, with HOME and PREFIX under root.
func isolateYarnEnvironment(t *testing.T) string {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "npm_config_") || strings.HasPrefix(lower, "yarn_") || strings.HasSuffix(lower, "_proxy") ||
			lower == "proxy" || key == "NODE_EXTRA_CA_CERTS" || key == "GIT_SSL_CAINFO" || key == "PREFIX" || key == "DESTDIR" {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("PREFIX", filepath.Join(root, "prefix"))
	project := filepath.Join(root, "parent", "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	return root
}

// testdataDir is absolute because tests change directory before reading fixtures.
var testdataDir, _ = filepath.Abs("testdata")

// writeYarnFixture copies testdata/<fixture> to path, substituting args into
// .tmpl fixtures.
func writeYarnFixture(t *testing.T, path, fixture string, args ...any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, fixture))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.HasSuffix(fixture, ".tmpl") {
		content = fmt.Sprintf(content, args...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestClassicUpstreamPrecedence(t *testing.T) {
	type source func(t *testing.T, root string)
	file := func(dir, name, fixture, value string) source {
		return func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, dir, name), fixture, value)
		}
	}
	env := func(key, value string) source {
		return func(t *testing.T, _ string) { t.Setenv(key, value) }
	}
	project, parent, home := "parent/project", "parent", "home"
	for _, test := range []struct {
		name    string
		command []string
		sources []source
		https   string
	}{
		{"cli beats rc-arg", []string{"--https-proxy=http://cli:1", "add", "x"},
			[]source{file(project, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://rc-arg:1")}, "http://cli:1"},
		{"cli after the command", []string{"add", "x", "--https-proxy", "http://cli:1"},
			[]source{env("YARN_HTTPS_PROXY", "http://env:1")}, "http://cli:1"},
		{"rc-arg beats YARN_HTTPS_PROXY", nil, []source{
			file(project, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://rc-arg:1"), env("YARN_HTTPS_PROXY", "http://env:1"),
		}, "http://rc-arg:1"},
		// Yarn merges rc-args from the cwd chain first and the home file last.
		{"home rc-arg beats project rc-arg", nil, []source{
			file(project, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://project-arg:1"),
			file(home, ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://home-arg:1"),
		}, "http://home-arg:1"},
		{"YARN_HTTPS_PROXY beats project .yarnrc", nil, []source{
			env("YARN_HTTPS_PROXY", "http://env:1"), file(project, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1"),
		}, "http://env:1"},
		{"lowercase yarn_https_proxy", nil, []source{env("yarn_https_proxy", "http://env:1")}, "http://env:1"},
		{"project beats home .yarnrc", nil, []source{
			file(project, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1"),
			file(home, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://home:1"),
		}, "http://project:1"},
		// Yarn reads the cwd, home, and global files before parent directories.
		{"home beats parent .yarnrc", nil, []source{
			file(parent, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://parent:1"),
			file(home, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://home:1"),
		}, "http://home:1"},
		{"parent .yarnrc", nil, []source{file(parent, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://parent:1")}, "http://parent:1"},
		{"global yarnrc", nil, []source{file("prefix/etc", "yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://global:1")}, "http://global:1"},
		{"home .yarnrc beats npm_config_https_proxy", nil, []source{
			file(home, ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://home:1"), env("npm_config_https_proxy", "http://npm-env:1"),
		}, "http://home:1"},
		{"npm_config_https_proxy beats project .npmrc", nil, []source{
			env("npm_config_https_proxy", "http://npm-env:1"), file(project, ".npmrc", "yarnrc/https-proxy.npmrc.tmpl", "http://npmrc:1"),
		}, "http://npm-env:1"},
		{".npmrc https-proxy beats .yarnrc proxy", nil, []source{
			file(project, ".npmrc", "yarnrc/https-proxy.npmrc.tmpl", "http://npmrc:1"),
			file(project, ".yarnrc", "yarnrc/proxy.yarnrc.tmpl", "http://yarn-proxy:1"),
		}, "http://npmrc:1"},
		{"proxy only is used for https", nil, []source{file(project, ".yarnrc", "yarnrc/proxy.yarnrc.tmpl", "http://yarn-proxy:1")}, "http://yarn-proxy:1"},
		{"HTTPS_PROXY beats https_proxy", nil, []source{env("HTTPS_PROXY", "http://upper:1"), env("https_proxy", "http://lower:1")}, "http://upper:1"},
		{"https_proxy beats HTTP_PROXY", nil, []source{env("https_proxy", "http://lower:1"), env("HTTP_PROXY", "http://http:1")}, "http://lower:1"},
		{"HTTP_PROXY is used for https", nil, []source{env("HTTP_PROXY", "http://http:1")}, "http://http:1"},
		{"ALL_PROXY is ignored", nil, []source{env("ALL_PROXY", "http://all:1")}, ""},
		{"YARN_HTTP_PROXY is ignored", nil, []source{env("YARN_HTTP_PROXY", "http://yarn-http:1")}, ""},
		{"https-proxy false disables the environment", nil, []source{
			file(project, ".yarnrc", "yarnrc/disabled.yarnrc", ""), env("HTTPS_PROXY", "http://upper:1"),
		}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			for _, add := range test.sources {
				add(t, root)
			}
			config, err := fakeYarn(t, "1.22.22").UpstreamProxy(test.command)
			if err != nil {
				t.Fatal(err)
			}
			if config.HTTPSProxy != test.https {
				t.Fatalf("HTTPSProxy = %q, want %q", config.HTTPSProxy, test.https)
			}
		})
	}
}

func TestClassicUpstreamHTTPProxy(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "home", ".yarnrc"), "yarnrc/proxy.yarnrc.tmpl", "http://yarn-proxy:1")
	t.Setenv("HTTP_PROXY", "http://env:1")
	config, err := fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err != nil || config.HTTPProxy != "http://yarn-proxy:1" {
		t.Fatalf("HTTPProxy = %q (error %v)", config.HTTPProxy, err)
	}
}

func TestClassicUpstreamNoProxyOnlyForEnvironment(t *testing.T) {
	root := isolateYarnEnvironment(t)
	t.Setenv("HTTPS_PROXY", "http://upper:1")
	t.Setenv("NO_PROXY", "registry.yarnpkg.com")
	config, err := fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err != nil || config.HTTPSProxy != "http://upper:1" || config.NoProxy != "registry.yarnpkg.com" {
		t.Fatalf("config = %+v (error %v), want the environment's proxy and bypass list", config, err)
	}
	// Yarn passes a configured proxy to its HTTP client, which then ignores NO_PROXY.
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1")
	config, err = fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err != nil || config.HTTPSProxy != "http://project:1" || config.NoProxy != "" {
		t.Fatalf("config = %+v (error %v), want the configured proxy without a bypass list", config, err)
	}
}

func TestClassicUpstreamHonorsCwdOption(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", "pkg", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://pkg:1")
	// Yarn Classic accepts --cwd anywhere among the arguments it parses itself;
	// create hands the arguments after its package to that package.
	for command, want := range map[string]string{
		"--cwd pkg add x": "http://pkg:1", "add x --cwd pkg": "http://pkg:1", "add x --cwd=pkg": "http://pkg:1",
		"create foo --cwd pkg": "", "create foo --cwd pkg -- y": "http://pkg:1",
	} {
		config, err := fakeYarn(t, "1.22.22").UpstreamProxy(strings.Fields(command))
		if err != nil || config.HTTPSProxy != want {
			t.Fatalf("%q: HTTPSProxy = %q (error %v), want %q", command, config.HTTPSProxy, err, want)
		}
	}
}

// Yarn reads rc-args from the first exact --cwd, following an rc-arg --cwd,
// and its other configuration from the project root of the last --cwd.
func TestClassicCwdSelectsConfiguration(t *testing.T) {
	type file struct{ dir, name, fixture, value string }
	for _, test := range []struct {
		name    string
		files   []file
		command string
		want    string
		fails   bool
	}{
		{"rc-args come from the first --cwd", []file{
			{"one", ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://one:1"}, {"two", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://two:1"},
		}, "--cwd one --cwd two add x", "http://one:1", false},
		{"the = form does not choose the rc-args", []file{
			{"one", ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://one:1"}, {"two", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://two:1"},
		}, "--cwd=one --cwd two add x", "http://two:1", false},
		{"the last --cwd chooses the configuration files", []file{
			{"one", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://one:1"}, {"two", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://two:1"},
		}, "--cwd one add x --cwd=two", "http://two:1", false},
		{"an rc-arg --cwd moves Yarn", []file{
			{".", ".yarnrc", "yarnrc/rc-arg-cwd.yarnrc.tmpl", "two"}, {"two", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://two:1"},
		}, "add x", "http://two:1", false},
		{"a command-line --cwd beats an rc-arg --cwd", []file{
			{".", ".yarnrc", "yarnrc/rc-arg-cwd.yarnrc.tmpl", "two"}, {"two", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://two:1"},
		}, "add x --cwd=.", "", false},
		{"recursive rc-arg --cwd fails", []file{
			{"one", ".yarnrc", "yarnrc/rc-arg-cwd.yarnrc.tmpl", "../two"}, {"two", ".yarnrc", "yarnrc/rc-arg-cwd.yarnrc.tmpl", "../one"},
		}, "--cwd one add x", "", true},
		{"a folder without package.json is not the project", []file{
			{".", "package.json", "workspaces/empty.json", ""}, {"sub", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://sub:1"},
		}, "--cwd sub add x", "", false},
		{"--use-yarnrc adds the highest file", []file{
			{".", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1"}, {"..", "extra", "yarnrc/https-proxy.yarnrc.tmpl", "http://extra:1"},
		}, "--use-yarnrc ../extra add x", "http://extra:1", false},
		{"--use-yarnrc rc-args apply", []file{{"..", "extra", "yarnrc/rc-arg.yarnrc.tmpl", "http://extra:1"}},
			"add x --use-yarnrc ../extra", "http://extra:1", false},
		{"--no-default-rc drops the default files", []file{
			{".", ".yarnrc", "yarnrc/https-proxy.yarnrc.tmpl", "http://project:1"}, {"../../home", ".yarnrc", "yarnrc/rc-arg.yarnrc.tmpl", "http://home:1"},
		}, "--no-default-rc add x", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			project := filepath.Join(root, "parent", "project")
			for _, file := range test.files {
				writeYarnFixture(t, filepath.Join(project, file.dir, file.name), file.fixture, file.value)
			}
			config, err := fakeYarn(t, "1.22.22").UpstreamProxy(strings.Fields(test.command))
			if test.fails {
				if err == nil {
					t.Fatal("want an error")
				}
				return
			}
			if err != nil || config.HTTPSProxy != test.want {
				t.Fatalf("HTTPSProxy = %q (error %v), want %q", config.HTTPSProxy, err, test.want)
			}
		})
	}
}

// `yarn workspace <name> <command>` runs <command> inside the workspace, so
// that directory's .yarnrc decides which proxy and trust Yarn would have used.
func TestClassicWorkspaceDiscoversFromTheWorkspace(t *testing.T) {
	for _, test := range []struct {
		name, root string
		// members maps a directory below the project to its package name.
		members map[string]string
		rcDir   string
		rc      string
		command []string
		want    string
	}{
		{"named workspace", "root-array.json", map[string]string{"a": "a", "packages/b": "b"}, "a",
			"yarnrc/https-proxy.yarnrc.tmpl", []string{"workspace", "a", "add", "x"}, "http://rc:1"},
		{"rc-arg proxy in the workspace", "root-array.json", map[string]string{"a": "a", "packages/b": "b"}, "a",
			"yarnrc/rc-arg.yarnrc.tmpl", []string{"workspace", "a", "add", "x"}, "http://rc:1"},
		{"another workspace is not affected", "root-array.json", map[string]string{"a": "a", "packages/b": "b"}, "a",
			"yarnrc/https-proxy.yarnrc.tmpl", []string{"workspace", "b", "add", "x"}, ""},
		{"unknown name keeps the starting directory", "root-array.json", map[string]string{"a": "a"}, "a",
			"yarnrc/https-proxy.yarnrc.tmpl", []string{"workspace", "missing", "add", "x"}, ""},
		{"glob with a wildcard", "root-array.json", map[string]string{"packages/b": "b"}, "packages/b",
			"yarnrc/https-proxy.yarnrc.tmpl", []string{"workspace", "b", "add", "x"}, "http://rc:1"},
		{"recursive glob in the packages form", "root-packages.json", map[string]string{"packages/x/y": "y"}, "packages/x/y",
			"yarnrc/https-proxy.yarnrc.tmpl", []string{"workspace", "y", "add", "x"}, "http://rc:1"},
		{"rc-arg scoped to the inner command", "root-array.json", map[string]string{"a": "a"}, "a",
			"yarnrc/rc-arg-add.yarnrc.tmpl", []string{"workspace", "a", "add", "x"}, "http://rc:1"},
		{"rc-arg scoped to another command", "root-array.json", map[string]string{"a": "a"}, "a",
			"yarnrc/rc-arg-add.yarnrc.tmpl", []string{"workspace", "a", "remove", "x"}, ""},
		{"options before the command", "root-array.json", map[string]string{"a": "a"}, "a",
			"yarnrc/https-proxy.yarnrc.tmpl", []string{"--non-interactive", "workspace", "a", "add", "x"}, "http://rc:1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			project := filepath.Join(root, "parent", "project")
			writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/"+test.root)
			for dir, name := range test.members {
				writeYarnFixture(t, filepath.Join(project, dir, "package.json"), "workspaces/member.json.tmpl", name)
			}
			writeYarnFixture(t, filepath.Join(project, test.rcDir, ".yarnrc"), test.rc, "http://rc:1")
			config, err := fakeYarn(t, "1.22.22").UpstreamProxy(test.command)
			if err != nil || config.HTTPSProxy != test.want {
				t.Fatalf("HTTPSProxy = %q (error %v), want %q", config.HTTPSProxy, err, test.want)
			}
		})
	}
}

// writeWorkspaceMembers writes each member's package.json and a .yarnrc whose
// proxy names it, so the proxy read back names the workspace Yarn runs in.
func writeWorkspaceMembers(t *testing.T, project string, members map[string]string) {
	t.Helper()
	for dir, name := range members {
		writeYarnFixture(t, filepath.Join(project, dir, "package.json"), "workspaces/member.json.tmpl", name)
		writeYarnFixture(t, filepath.Join(project, dir, ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://"+name+":1")
	}
}

// Yarn Classic finds the workspace root, its members, and their names with
// its own glob and micromatch rules.
func TestClassicWorkspaceResolution(t *testing.T) {
	insensitive := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	for _, test := range []struct {
		name, patterns string
		members        map[string]string
		setup          func(t *testing.T, project string)
		command        string
		// want names the workspace whose configuration is used.
		want string
		err  error
	}{
		{"a nohoist-only manifest is skipped", `["packages/*"]`, map[string]string{"packages/a": "a"},
			func(t *testing.T, project string) {
				writeYarnFixture(t, filepath.Join(project, "packages", "nh", "package.json"), "workspaces/nohoist.json")
			}, "--cwd packages/nh workspace a add x", "a", nil},
		{"a project outside the patterns has no root", `["packages/*"]`, map[string]string{"packages/a": "a", "other": "other"},
			nil, "--cwd other workspace a add x", "other", nil},
		{"a project is a member", `["packages/*"]`, map[string]string{"packages/a": "a", "packages/c": "c"},
			nil, "--cwd packages/c workspace a add x", "a", nil},
		{"a negated pattern excludes the project", `["packages/*", "!packages/c"]`, map[string]string{"packages/a": "a", "packages/c": "c"},
			nil, "--cwd packages/c workspace a add x", "c", nil},
		{"a root without private is refused", `["packages/*"]`, map[string]string{"packages/a": "a"},
			func(t *testing.T, project string) {
				writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root-not-private.json.tmpl", `["packages/*"]`)
			}, "workspace a add x", "", nil},
		{"a leading ! is literal in the members glob", `["packages/*", "!packages/a"]`, map[string]string{"packages/a": "a"},
			nil, "workspace a add x", "a", nil},
		{"braces expand", `["{apps,libs}/*"]`, map[string]string{"libs/b": "b"}, nil, "workspace b add x", "b", nil},
		{"a negated class excludes", `["packages/[!x]"]`, map[string]string{"packages/b": "b", "packages/x": "x"},
			nil, "workspace x add x", "", nil},
		{"a negated class includes", `["packages/[!x]"]`, map[string]string{"packages/b": "b"}, nil, "workspace b add x", "b", nil},
		{"wildcards skip dot directories", `["packages/*"]`, map[string]string{"packages/.h": "h"}, nil, "workspace h add x", "", nil},
		{"a dot pattern matches dot directories", `["packages/.*"]`, map[string]string{"packages/.h": "h"}, nil, "workspace h add x", "h", nil},
		{"a leading ./ and repeated slashes", `["./packages//*/"]`, map[string]string{"packages/b": "b"}, nil, "workspace b add x", "b", nil},
		{"a symlinked directory matches", `["packages/*"]`, nil, func(t *testing.T, project string) {
			writeWorkspaceMembers(t, filepath.Dir(project), map[string]string{"linked": "l"})
			if err := os.MkdirAll(filepath.Join(project, "packages"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(project), "linked"), filepath.Join(project, "packages", "link")); err != nil {
				t.Skip(err)
			}
		}, "workspace l add x", "l", nil},
		{"wildcard segments are case-sensitive", `["packages/B*"]`, map[string]string{"packages/b": "b"}, nil, "workspace b add x", "", nil},
		{"literal segments compare as the filesystem does", `["Packages/*"]`, map[string]string{"packages/b": "b"},
			nil, "workspace b add x", map[bool]string{true: "b"}[insensitive], nil},
		{"globstar does not reach node_modules", `["packages/**"]`, map[string]string{"packages/node_modules/n": "n"},
			nil, "workspace n add x", "", nil},
		{"a wildcard matches node_modules", `["packages/*"]`, map[string]string{"packages/node_modules": "nm"},
			nil, "workspace nm add x", "nm", nil},
		{"a member needs a version", `["packages/*"]`, nil, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(project, "packages", "v", "package.json"), "workspaces/member-without-version.json.tmpl", "v")
			writeYarnFixture(t, filepath.Join(project, "packages", "v", ".yarnrc"), "yarnrc/https-proxy.yarnrc.tmpl", "http://v:1")
		}, "workspace v add x", "", nil},
		// A member without package.json is a project only from the root, so its
		// rc-args show where Yarn runs.
		{"a member with only yarn.json", `["packages/*"]`, nil, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(project, "packages", "y", "yarn.json"), "workspaces/member.json.tmpl", "y")
			writeYarnFixture(t, filepath.Join(project, "packages", "y", ".yarnrc"), "yarnrc/rc-arg.yarnrc.tmpl", "http://y:1")
		}, "workspace y add x", "y", nil},
		// Yarn reads package.json for both manifests, a duplicate that fails
		// every workspace lookup, so the command is left for Yarn to report.
		{"a member with both manifests fails in Yarn", `["packages/*"]`, map[string]string{"packages/a": "a", "packages/d": "d"}, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(project, "packages", "d", "yarn.json"), "workspaces/member.json.tmpl", "d")
		}, "workspace a add x", "", nil},
		{"a duplicate name fails in Yarn", `["packages/*"]`, map[string]string{"packages/a": "a"}, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(project, "packages", "b", "package.json"), "workspaces/member.json.tmpl", "a")
		}, "workspace a add x", "", nil},
		{"nested workspace commands", `["packages/*"]`, map[string]string{"packages/a": "a", "packages/b": "b"},
			nil, "workspace a workspace b add x", "b", nil},
		{"an unknown name with patterns SCFW cannot evaluate fails", `["packages/+(a|b)"]`, map[string]string{"packages/a": "a"},
			nil, "workspace a add x", "", errors.New("brace ranges")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			project := filepath.Join(root, "parent", "project")
			writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root.json.tmpl", test.patterns)
			writeWorkspaceMembers(t, project, test.members)
			if test.setup != nil {
				test.setup(t, project)
			}
			config, err := fakeYarn(t, "1.22.22").UpstreamProxy(strings.Fields(test.command))
			if test.err != nil {
				if err == nil || !strings.Contains(err.Error(), test.err.Error()) {
					t.Fatalf("error = %v, want %v", err, test.err)
				}
				return
			}
			want := ""
			if test.want != "" {
				want = "http://" + test.want + ":1"
			}
			if err != nil || config.HTTPSProxy != want {
				t.Fatalf("HTTPSProxy = %q (error %v), want %q", config.HTTPSProxy, err, want)
			}
		})
	}
}

// The walk is bounded, and a project beyond the bound fails closed.
func TestClassicWorkspaceWalkIsBounded(t *testing.T) {
	root := isolateYarnEnvironment(t)
	project := filepath.Join(root, "parent", "project")
	writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root.json.tmpl", `["packages/**"]`)
	writeWorkspaceMembers(t, project, map[string]string{"packages/a": "a", "packages/b": "b", "packages/c": "c"})
	maximum := maxWorkspaceEntries
	maxWorkspaceEntries = 5
	t.Cleanup(func() { maxWorkspaceEntries = maximum })
	if _, err := fakeYarn(t, "1.22.22").UpstreamProxy([]string{"workspace", "c", "add", "x"}); !errors.Is(err, errWorkspaceBound) {
		t.Fatalf("error = %v, want the bound", err)
	}
}

func TestClassicUpstreamRejectsInvalidURLWithoutCredentials(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc"), "yarnrc/invalid.yarnrc")
	_, err := fakeYarn(t, "1.22.22").UpstreamProxy(nil)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error = %v, want a credential-free error", err)
	}
}
