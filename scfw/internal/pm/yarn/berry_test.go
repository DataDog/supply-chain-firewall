// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBerryProxyCommandLeavesArgumentsUnchanged(t *testing.T) {
	isolateYarnEnvironment(t)
	command := []string{"--cwd", "pkg", "add", "x", "--", "--proxy"}
	manager := fakeYarn(t, "4.18.1")
	spec, err := manager.ProxyCommand(context.Background(), command, testClientConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Executable != manager.Executable() || !slices.Equal(spec.Args, command) {
		t.Fatalf("command = %s %q, want %q", spec.Executable, spec.Args, command)
	}
}

func TestBerryProxyCommandEnvironment(t *testing.T) {
	isolateYarnEnvironment(t)
	config := testClientConfig(t)
	t.Setenv("yarn_https_proxy", "http://old:1")
	t.Setenv("YARN_NPM_REGISTRY_SERVER", "https://r.test/")
	spec, err := fakeYarn(t, "4.18.1").ProxyCommand(context.Background(), []string{"install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	ca := config.CACertificatePath
	for key, value := range map[string]string{
		"YARN_HTTPS_PROXY": config.URL, "YARN_HTTP_PROXY": config.URL, "YARN_HTTPS_CA_FILE_PATH": ca,
		"yarn_https_proxy": config.URL, "HTTPS_PROXY": config.URL, "NO_PROXY": "",
		"GIT_SSL_CAINFO": ca, "NODE_EXTRA_CA_CERTS": ca,
	} {
		if actual, found := spec.EnvOverrides[key]; !found || actual != value {
			t.Errorf("%s = %q (present %v), want %q", key, actual, found, value)
		}
	}
	// Yarn 4 rejects YARN_CA_FILE_PATH, and Plug'n'Play owns NODE_OPTIONS.
	for _, key := range []string{"YARN_CA_FILE_PATH", "NODE_OPTIONS", "YARN_PROXY", "YARN_NPM_REGISTRY_SERVER"} {
		if _, found := spec.EnvOverrides[key]; found {
			t.Errorf("%s must not be overridden", key)
		}
	}
}

func TestBerryProxyCommandRefusesNetworkSettings(t *testing.T) {
	root := isolateYarnEnvironment(t)
	writeYarnFixture(t, filepath.Join(root, "parent", "project", ".yarnrc.yml"), "yarnrc-yml/network-proxy.yml")
	_, err := fakeYarn(t, "4.18.1").ProxyCommand(context.Background(), []string{"install"}, testClientConfig(t))
	if err == nil || !strings.Contains(err.Error(), "networkSettings") {
		t.Fatalf("error = %v", err)
	}
}
