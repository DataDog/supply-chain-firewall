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
// would not receive SCFW's options, so the command runs there directly.
func TestClassicProxyCommandRunsWorkspaceCommandsInTheWorkspace(t *testing.T) {
	root := isolateYarnEnvironment(t)
	project := filepath.Join(root, "parent", "project")
	writeYarnFixture(t, filepath.Join(project, "package.json"), "workspaces/root-array.json")
	writeYarnFixture(t, filepath.Join(project, "a", "package.json"), "workspaces/member.json.tmpl", "a")
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(t)
	flags := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL}
	for _, test := range []struct {
		name    string
		command []string
		want    []string
	}{
		{"named workspace", []string{"workspace", "a", "add", "x", "--dev"},
			append(slices.Clone(flags), "--cwd", filepath.Join(directory, "a"), "add", "x", "--dev")},
		{"options before the command stay with the outer Yarn", []string{"--registry", "http://r:1", "--cwd", ".", "workspace", "a", "add", "x"},
			append(slices.Clone(flags), "--cwd", filepath.Join(directory, "a"), "add", "x")},
		{"arguments after the separator are kept", []string{"workspace", "a", "add", "x", "--", "--proxy", "y"},
			append(slices.Clone(flags), "--cwd", filepath.Join(directory, "a"), "add", "x", "--", "--proxy", "y")},
		{"unknown workspace is left for Yarn to report", []string{"workspace", "missing", "add", "x"},
			append(slices.Clone(flags), "workspace", "missing", "add", "x")},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec, err := fakeYarn(t, "1.22.22").ProxyCommand(context.Background(), test.command, config)
			if err != nil || !slices.Equal(spec.Args, test.want) {
				t.Fatalf("args = %q (error %v), want %q", spec.Args, err, test.want)
			}
		})
	}
}
