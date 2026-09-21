// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNetrcCredentials(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "netrc")
	if err := os.WriteFile(path, []byte("machine packages.example.com login reader password secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETRC", path)

	credentials, err := loadNetrcCredentials()
	if err != nil {
		t.Fatalf("loadNetrcCredentials() error = %v", err)
	}
	credential, ok := credentials["packages.example.com"]
	if !ok {
		t.Fatal("loadNetrcCredentials() did not return the configured machine")
	}
	if credential.username != "reader" || credential.password != "secret" {
		t.Fatalf("loadNetrcCredentials() = %#v", credential)
	}
}

func TestNPMCredentialFilesHonorsUserConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.npmrc")
	t.Setenv("npm_config_userconfig", path)
	t.Setenv("NPM_CONFIG_USERCONFIG", "")

	files := npmCredentialFiles()
	if len(files) == 0 || files[0] != path {
		t.Fatalf("npmCredentialFiles() = %v, want first file %q", files, path)
	}
}
