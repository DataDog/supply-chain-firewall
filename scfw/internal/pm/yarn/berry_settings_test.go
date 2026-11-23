// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBerryUpstreamPrecedence(t *testing.T) {
	type source func(t *testing.T, root string)
	file := func(dir, name, fixture string, args ...any) source {
		return func(t *testing.T, root string) {
			writeYarnFixture(t, filepath.Join(root, dir, name), "yarnrc-yml/"+fixture, args...)
		}
	}
	env := func(key, value string) source {
		return func(t *testing.T, _ string) { t.Setenv(key, value) }
	}
	project, parent, home := "parent/project", "parent", "home"
	for _, test := range []struct {
		name        string
		sources     []source
		https, http string
	}{
		{"YARN_HTTPS_PROXY beats project rc", []source{
			env("YARN_HTTPS_PROXY", "http://env:1"), file(project, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://project:1"),
		}, "http://env:1", ""},
		{"lowercase yarn_https_proxy", []source{env("yarn_https_proxy", "http://env:1")}, "http://env:1", ""},
		{"project beats parent rc", []source{
			file(project, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://project:1"),
			file(parent, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://parent:1"),
		}, "http://project:1", ""},
		{"parent beats home rc", []source{
			file(parent, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://parent:1"),
			file(home, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://home:1"),
		}, "http://parent:1", ""},
		{"home rc", []source{file(home, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://home:1")}, "http://home:1", ""},
		{"standard variables are ignored", []source{
			env("HTTPS_PROXY", "http://upper:1"), env("HTTP_PROXY", "http://http:1"), env("ALL_PROXY", "http://all:1"),
		}, "", ""},
		{"httpProxy does not cover https", []source{file(project, ".yarnrc.yml", "http-proxy.yml.tmpl", "http://http:1")}, "", "http://http:1"},
		{"YARN_RC_FILENAME renames project files only", []source{
			env("YARN_RC_FILENAME", ".custom.yml"),
			file(project, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://ignored:1"),
			file(parent, ".custom.yml", "http-proxy.yml.tmpl", "http://custom:1"),
			file(home, ".yarnrc.yml", "https-proxy.yml.tmpl", "http://home:1"),
		}, "http://home:1", "http://custom:1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			for _, add := range test.sources {
				add(t, root)
			}
			config, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil)
			if err != nil {
				t.Fatal(err)
			}
			if config.HTTPSProxy != test.https || config.HTTPProxy != test.http || config.NoProxy != "" {
				t.Fatalf("config = %+v, want https %q http %q", config, test.https, test.http)
			}
		})
	}
}

// Yarn 4 uses the first variable named YARN_RC_FILENAME in any case, even an
// empty one, which makes it fail.
func TestBerryRCFilenameFirstEntry(t *testing.T) {
	root := isolateYarnEnvironment(t)
	project := filepath.Join(root, "parent", "project")
	writeYarnFixture(t, filepath.Join(project, ".first.yml"), "yarnrc-yml/https-proxy.yml.tmpl", "http://first:1")
	writeYarnFixture(t, filepath.Join(project, ".second.yml"), "yarnrc-yml/https-proxy.yml.tmpl", "http://second:1")
	t.Setenv("YARN_RC_FILENAME", ".first.yml")
	t.Setenv("yarn_rc_filename", ".second.yml")
	config, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil)
	if err != nil || config.HTTPSProxy != "http://first:1" {
		t.Fatalf("HTTPSProxy = %q (error %v), want the first entry's", config.HTTPSProxy, err)
	}
	t.Setenv("YARN_RC_FILENAME", "")
	if _, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil); err == nil || !strings.Contains(err.Error(), "YARN_RC_FILENAME") {
		t.Fatalf("an empty first entry must fail like Yarn: %v", err)
	}
}

func TestBerryUpstreamInterpolation(t *testing.T) {
	root := isolateYarnEnvironment(t)
	rc := filepath.Join(root, "parent", "project", ".yarnrc.yml")
	writeYarnFixture(t, rc, "yarnrc-yml/interpolation.yml")
	for value, want := range map[string]string{"": "http://fallback:1", "http://corp:1": "http://corp:1"} {
		t.Setenv("CORP_PROXY", value)
		config, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil)
		if err != nil || config.HTTPSProxy != want {
			t.Fatalf("CORP_PROXY=%q: HTTPSProxy = %q (error %v), want %q", value, config.HTTPSProxy, err, want)
		}
	}
	writeYarnFixture(t, rc, "yarnrc-yml/missing-variable.yml")
	if _, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil); err == nil {
		t.Fatal("an unset variable without a fallback must fail like Yarn")
	}
}

func TestBerryRefusesPerHostOverrides(t *testing.T) {
	for _, test := range []struct {
		fixture, dir, want string
	}{
		{"network-proxy.yml", "parent/project", "networkSettings"},
		{"network-proxy.yml", "home", "networkSettings"},
		{"network-ca.yml", "parent/project", "networkSettings"},
		{"client-cert.yml", "parent", "client certificates"},
		{"network-enable-only.yml", "parent/project", ""},
	} {
		t.Run(test.fixture+" in "+test.dir, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			writeYarnFixture(t, filepath.Join(root, test.dir, ".yarnrc.yml"), "yarnrc-yml/"+test.fixture)
			_, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil)
			if test.want == "" {
				if err != nil {
					t.Fatalf("error = %v, want none", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, test.want)
			}
		})
	}
	t.Run("client certificate from the environment", func(t *testing.T) {
		isolateYarnEnvironment(t)
		t.Setenv("YARN_HTTPS_CERT_FILE_PATH", "/certs/client.pem")
		if _, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil); err == nil || !strings.Contains(err.Error(), "client certificates") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestBerryUpstreamHonorsCwdOption(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", "pkg", ".yarnrc.yml"), "yarnrc-yml/https-proxy.yml.tmpl", "http://pkg:1")
	config, err := fakeYarn(t, "4.18.1").UpstreamProxy([]string{"--cwd", "pkg", "add", "x"})
	if err != nil || config.HTTPSProxy != "http://pkg:1" {
		t.Fatalf("HTTPSProxy = %q (error %v)", config.HTTPSProxy, err)
	}
	// Yarn 4 also accepts `yarn add <packages> --cwd <dir>`.
	config, err = fakeYarn(t, "4.18.1").UpstreamProxy([]string{"add", "x", "--cwd", "pkg"})
	if err != nil || config.HTTPSProxy != "http://pkg:1" {
		t.Fatalf("trailing --cwd: HTTPSProxy = %q (error %v)", config.HTTPSProxy, err)
	}
	// Yarn 4 rejects a --cwd anywhere else.
	config, err = fakeYarn(t, "4.18.1").UpstreamProxy([]string{"--immutable", "add", "x", "--cwd", "pkg"})
	if err != nil || config.HTTPSProxy != "" {
		t.Fatalf("misplaced --cwd: HTTPSProxy = %q (error %v)", config.HTTPSProxy, err)
	}
	writeYarnFixture(t, filepath.Join(root, "parent", "project", "pkg", ".yarnrc.yml"), "yarnrc-yml/network-proxy.yml")
	if _, err := fakeYarn(t, "4.18.1").UpstreamProxy([]string{"add", "x", "--cwd", "pkg"}); err == nil || !strings.Contains(err.Error(), "networkSettings") {
		t.Fatalf("trailing --cwd must still refuse networkSettings: %v", err)
	}
}

func TestBerryUpstreamRejectsInvalidURLWithoutCredentials(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc.yml"), "yarnrc-yml/invalid.yml")
	_, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error = %v, want a credential-free error", err)
	}
}

// writeBerryMembers writes each member's package.json and a .yarnrc.yml whose
// proxy names it.
func writeBerryMembers(t *testing.T, project string, members map[string]string) {
	t.Helper()
	for dir, name := range members {
		writeYarnFixture(t, filepath.Join(project, dir, "package.json"), "workspaces/member.json.tmpl", name)
		writeYarnFixture(t, filepath.Join(project, dir, ".yarnrc.yml"), "yarnrc-yml/https-proxy.yml.tmpl", "http://"+name+":1")
	}
}

// Yarn 4 runs workspace commands in the workspace, which reads the rc files
// from there up, and finds workspaces with fast-glob from its project.
func TestBerryWorkspaceDiscoversFromTheWorkspace(t *testing.T) {
	for _, test := range []struct {
		name, patterns string
		members        map[string]string
		setup          func(t *testing.T, project string)
		command        string
		want           string
	}{
		{"named workspace", `["packages/*"]`, map[string]string{"packages/a": "a", "packages/b": "b"}, nil, "workspace a add x", "a"},
		{"unknown name keeps the starting directory", `["packages/*"]`, map[string]string{"packages/a": "a"}, nil, "workspace z add x", ""},
		{"nested workspaces", `["packages/*"]`, nil, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(project, "packages", "a", "package.json"), "workspaces/member-with-workspaces.json.tmpl", "a", `["nested/*"]`)
			writeBerryMembers(t, project, map[string]string{"packages/a/nested/c": "c"})
		}, "workspace c add x", "c"},
		{"nested workspace commands", `["packages/*"]`, map[string]string{"packages/a": "a", "packages/b": "b"}, nil, "workspace a workspace b add x", "b"},
		{"a negated pattern excludes", `["packages/*", "!packages/a"]`, map[string]string{"packages/a": "a"}, nil, "workspace a add x", ""},
		{".yarn is ignored", `[".yarn/*"]`, map[string]string{".yarn/w": "w"}, nil, "workspace w add x", ""},
		{"node_modules is ignored", `["packages/*"]`, map[string]string{"packages/node_modules": "nm"}, nil, "workspace nm add x", ""},
		{"literal segments after a wildcard are case-sensitive", `["*/A"]`, map[string]string{"packages/a": "a"}, nil, "workspace a add x", ""},
		{"the topmost package.json is the project", `[]`, nil, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(filepath.Dir(project), "package.json"), "workspaces/root.json.tmpl", `["project/packages/*"]`)
			writeBerryMembers(t, project, map[string]string{"packages/a": "a"})
		}, "workspace a add x", "a"},
		{"a yarn.lock marks the project", `[]`, nil, func(t *testing.T, project string) {
			writeYarnFixture(t, filepath.Join(filepath.Dir(project), "package.json"), "workspaces/root.json.tmpl", `["project/packages/*"]`)
			writeBerryMembers(t, project, map[string]string{"packages/a": "a"})
			writeYarnFixture(t, filepath.Join(project, "yarn.lock"), "workspaces/empty.json")
		}, "workspace a add x", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			project := filepath.Join(root, "parent", "project")
			writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root.json.tmpl", test.patterns)
			writeBerryMembers(t, project, test.members)
			if test.setup != nil {
				test.setup(t, project)
			}
			config, err := fakeYarn(t, "4.18.1").UpstreamProxy(strings.Fields(test.command))
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

func TestBerryWorkspaceRefusesWhatSCFWCannotRoute(t *testing.T) {
	for _, test := range []struct {
		name, patterns, dir, manifest, fixture, command, want string
	}{
		{"networkSettings in the workspace", `["packages/*"]`, "packages/a", "workspaces/member.json.tmpl", "network-proxy.yml", "workspace a add x", "networkSettings"},
		{"foreach over a workspace with another proxy", `["packages/*"]`, "packages/a", "workspaces/member.json.tmpl", "https-proxy.yml.tmpl", "workspaces foreach -A install", "different httpsProxy"},
		{"foreach over a workspace with networkSettings", `["packages/*"]`, "packages/a", "workspaces/member.json.tmpl", "network-proxy.yml", "workspaces foreach -A install", "networkSettings"},
		{"an unknown name with patterns SCFW cannot evaluate", `["packages/*", "@(x)"]`, "packages/a", "workspaces/member.json.tmpl", "", "workspace z add x", "brace ranges"},
		// foreach also runs in workspaces SCFW cannot list, so it fails closed.
		{"foreach over a workspace SCFW cannot match", `["packages/*", "+(other)"]`, "other", "workspaces/member.json.tmpl", "network-proxy.yml", "workspaces foreach -A install", "could not list every workspace"},
		{"foreach over a malformed workspace", `["packages/*"]`, "packages/bad", "yarnrc-yml/invalid.yml", "https-proxy.yml.tmpl", "workspaces foreach -A install", "could not list every workspace"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := isolateYarnEnvironment(t)
			project := filepath.Join(root, "parent", "project")
			writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root.json.tmpl", test.patterns)
			writeYarnFixture(t, filepath.Join(project, test.dir, "package.json"), test.manifest, "a")
			if test.fixture != "" {
				writeYarnFixture(t, filepath.Join(project, test.dir, ".yarnrc.yml"), "yarnrc-yml/"+test.fixture, "http://a:1")
			}
			if _, err := fakeYarn(t, "4.18.1").UpstreamProxy(strings.Fields(test.command)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, test.want)
			}
		})
	}
}

// foreach downloads from every workspace's registries.
func TestBerryForeachMergesRegistries(t *testing.T) {
	root := isolateYarnEnvironment(t)
	project := filepath.Join(root, "parent", "project")
	writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root.json.tmpl", `["packages/*"]`)
	writeYarnFixture(t, filepath.Join(project, "packages", "a", "package.json"), "workspaces/member.json.tmpl", "a")
	writeYarnFixture(t, filepath.Join(project, "packages", "a", ".yarnrc.yml"), "yarnrc-yml/registries.yml")
	options, err := fakeYarn(t, "4.18.1").NpmClassifierOptions([]string{"workspaces", "foreach", "-A", "install"})
	if err != nil || !slices.Contains(options.RegistryURLs, "https://art.test/api/npm/corp/") || !slices.Contains(options.RegistryURLs, "https://registry.yarnpkg.com") {
		t.Fatalf("registries = %q (error %v)", options.RegistryURLs, err)
	}
}
