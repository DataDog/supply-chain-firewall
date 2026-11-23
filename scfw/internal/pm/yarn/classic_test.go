// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func testClientConfig(t *testing.T) proxy.ClientConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	writeYarnFixture(t, path, "tls/scfw-ca.pem")
	return proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: path}
}

func TestClassicProxyCommandPrependsProxyFlags(t *testing.T) {
	isolateYarnEnvironment(t)
	config := testClientConfig(t)
	manager := fakeYarn(t, "1.22.22")
	spec, err := manager.ProxyCommand(context.Background(), []string{"add", "x"}, config)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL, "add", "x"}
	if spec.Executable != manager.Executable() || !slices.Equal(spec.Args, want) {
		t.Fatalf("command = %s %q, want %q", spec.Executable, spec.Args, want)
	}
}

func TestClassicProxyCommandDropsUserProxyFlags(t *testing.T) {
	isolateYarnEnvironment(t)
	config := testClientConfig(t)
	command := []string{"--proxy", "http://p:1", "add", "x", "--https-proxy=http://q:1", "--", "--proxy", "http://r:1"}
	spec, err := fakeYarn(t, "1.22.22").ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL, "add", "x", "--", "--proxy", "http://r:1"}
	if !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q, want %q", spec.Args, want)
	}
}

// Yarn Classic hands the arguments after create's package to that package.
func TestClassicProxyCommandKeepsPackageArguments(t *testing.T) {
	isolateYarnEnvironment(t)
	config := testClientConfig(t)
	spec, err := fakeYarn(t, "1.22.22").ProxyCommand(context.Background(), []string{"--proxy", "http://p:1", "create", "foo", "--proxy", "http://q:1"}, config)
	want := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL, "create", "foo", "--proxy", "http://q:1"}
	if err != nil || !slices.Equal(spec.Args, want) {
		t.Fatalf("args = %q (error %v), want %q", spec.Args, err, want)
	}
}

func TestClassicProxyCommandEnvironment(t *testing.T) {
	isolateYarnEnvironment(t)
	config := testClientConfig(t)
	t.Setenv("yarn_https_proxy", "http://old:1")
	t.Setenv("NPM_CONFIG-PROXY", "http://old:1")
	t.Setenv("YARN_REGISTRY", "https://r.test/")
	spec, err := fakeYarn(t, "1.22.22").ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	ca := config.CACertificatePath
	for key, value := range map[string]string{
		"YARN_PROXY": config.URL, "YARN_HTTPS_PROXY": config.URL, "YARN_CAFILE": ca,
		"npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL, "npm_config_cafile": ca,
		"npm_config_noproxy": "scfw.invalid", "HTTPS_PROXY": config.URL, "http_proxy": config.URL,
		"NO_PROXY": "", "no_proxy": "", "GIT_SSL_CAINFO": ca, "NODE_EXTRA_CA_CERTS": ca,
		"yarn_https_proxy": config.URL, "NPM_CONFIG-PROXY": config.URL,
	} {
		if actual, found := spec.EnvOverrides[key]; !found || actual != value {
			t.Errorf("%s = %q (present %v), want %q", key, actual, found, value)
		}
	}
	if _, found := spec.EnvOverrides["YARN_REGISTRY"]; found {
		t.Error("unrelated Yarn configuration must not be overridden")
	}
}

func TestClassicProxyCommandRejectsUnreadableCA(t *testing.T) {
	isolateYarnEnvironment(t)
	config := proxy.ClientConfig{URL: "http://127.0.0.1:9", CACertificatePath: filepath.Join(t.TempDir(), "missing-secret.pem")}
	_, err := fakeYarn(t, "1.22.22").ProxyCommand(context.Background(), []string{"install"}, config)
	if err == nil || err.Error() != "read proxy CA certificate" {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(config.CACertificatePath); !os.IsNotExist(statErr) {
		t.Fatal("no CA may be created")
	}
}

// `yarn workspace <name> <command>` starts a second Yarn in the workspace that
// would not receive SCFW's options, so the command runs there directly. The
// launched command must select the configuration Yarn's inner process would.
func TestClassicProxyCommandRunsWorkspaceCommandsInTheWorkspace(t *testing.T) {
	root := isolateYarnEnvironment(t)
	project := filepath.Join(root, "parent", "project")
	writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root-array.json")
	writeYarnFixture(t, filepath.Join(project, ".yarnrc"), "yarnrc/rc-arg.yarnrc.tmpl", "http://project-arg:1")
	writeYarnFixture(t, filepath.Join(project, "a", "package.json"), "workspaces/member.json.tmpl", "a")
	writeYarnFixture(t, filepath.Join(project, "a", "extra"), "yarnrc/rc-arg.yarnrc.tmpl", "http://extra:1")
	writeYarnFixture(t, filepath.Join(project, "packages", "b", "package.json"), "workspaces/member.json.tmpl", "b")
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(directory, "a"), filepath.Join(directory, "packages", "b")
	config := testClientConfig(t)
	flags := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL}
	for _, test := range []struct {
		name, command, dir, args, proxy string
	}{
		{"named workspace", "workspace a add x --dev", a, "add x --dev", "http://project-arg:1"},
		{"options before the command stay with the outer Yarn", "--registry http://r:1 --cwd . workspace a add x", a, "add x", "http://project-arg:1"},
		{"options among the kept arguments stay with the outer Yarn", "workspace --cwd . a add x", a, "add x", "http://project-arg:1"},
		// Yarn passes the arguments after "--" to the inner Yarn without it.
		{"the separator is dropped", "workspace a add x -- --proxy http://y:1", a, "add x", "http://project-arg:1"},
		{"outer options before the name with a separator", "workspace --cwd . a add x -- y", a, "add x y", "http://project-arg:1"},
		// A relative --cwd walks rc files only up to the process directory.
		{"the inner --cwd is relative to the workspace", "workspace a add x --cwd sub", a, "add x --cwd sub", ""},
		{"the inner --use-yarnrc is relative to the workspace", "workspace a add x --use-yarnrc extra", a, "add x --use-yarnrc extra", "http://extra:1"},
		{"nested workspace commands", "workspace a workspace b add x", b, "add x", "http://project-arg:1"},
		{"unknown workspace is left for Yarn to report", "workspace missing add x", "", "workspace missing add x", "http://project-arg:1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := fakeYarn(t, "1.22.22")
			command := strings.Fields(test.command)
			spec, err := manager.ProxyCommand(context.Background(), command, config)
			want := append(slices.Clone(flags), strings.Fields(test.args)...)
			if err != nil || !slices.Equal(spec.Args, want) || spec.Dir != test.dir {
				t.Fatalf("command = %q in %q (error %v), want %q in %q", spec.Args, spec.Dir, err, want, test.dir)
			}
			upstream, err := manager.UpstreamProxy(command)
			if err != nil || upstream.HTTPSProxy != test.proxy {
				t.Fatalf("HTTPSProxy = %q (error %v), want %q", upstream.HTTPSProxy, err, test.proxy)
			}
			// Without SCFW's options, the launched command in its directory
			// selects the same configuration.
			if spec.Dir != "" {
				t.Chdir(spec.Dir)
			}
			launched, err := manager.UpstreamProxy(spec.Args[len(flags):])
			if err != nil || launched.HTTPSProxy != test.proxy {
				t.Fatalf("launched HTTPSProxy = %q (error %v), want %q", launched.HTTPSProxy, err, test.proxy)
			}
		})
	}
}
