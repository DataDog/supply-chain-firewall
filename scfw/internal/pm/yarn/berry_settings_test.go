// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"path/filepath"
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
}

func TestBerryUpstreamRejectsInvalidURLWithoutCredentials(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc.yml"), "yarnrc-yml/invalid.yml")
	_, err := fakeYarn(t, "4.18.1").UpstreamProxy(nil)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error = %v, want a credential-free error", err)
	}
}
