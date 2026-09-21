// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"strings"
	"testing"
)

func TestBunProxyRegistryPreservesAuthentication(t *testing.T) {
	got, ok := bunProxyRegistry(map[string]any{"url": "https://registry.example", "token": "secret"}, "http://proxy/").(map[string]any)
	if !ok || got["url"] != "http://proxy/" || got["token"] != "secret" {
		t.Fatalf("bunProxyRegistry() = %#v", got)
	}
}

func TestPrepareRemovesRegistryEnvironment(t *testing.T) {
	t.Setenv("BUN_CONFIG_REGISTRY", "https://environment.example/")
	prepared, err := (&Manager{configuration: map[string]any{}}).Prepare("bun", []string{"install"}, "http://proxy/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() { _ = prepared.Cleanup() })
	if strings.Contains(strings.Join(prepared.Env, "\n"), "BUN_CONFIG_REGISTRY=") {
		t.Errorf("environment still contains BUN_CONFIG_REGISTRY: %v", prepared.Env)
	}
}

func TestMergeMapsPreservesUnrelatedInstallConfiguration(t *testing.T) {
	destination := map[string]any{"install": map[string]any{"cache": true}}
	mergeMaps(destination, map[string]any{"install": map[string]any{"exact": true}})
	install := destination["install"].(map[string]any)
	if install["cache"] != true || install["exact"] != true {
		t.Fatalf("merged install config = %#v", install)
	}
}
