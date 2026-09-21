// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"strings"
	"testing"
)

func TestPrepareUsesProxyAndFrozenLockfile(t *testing.T) {
	prepared, err := (Manager{}).Prepare("pnpm", []string{"install"}, "http://proxy/default/", map[string]string{"@private": "http://proxy/private/"})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	joined := strings.Join(prepared.Args, " ")
	for _, expected := range []string{"--registry=http://proxy/default/", "--@private:registry=http://proxy/private/", "--frozen-lockfile"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("args = %q, missing %q", joined, expected)
		}
	}
}

func TestPrepareDoesNotFreezeUnrelatedCommand(t *testing.T) {
	prepared, err := (Manager{}).Prepare("pnpm", []string{"list"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	joined := strings.Join(prepared.Args, " ")
	if strings.Contains(joined, "--frozen-lockfile") {
		t.Errorf("args = %q, should not force frozen lockfile", joined)
	}
	if !strings.Contains(joined, "--registry=http://proxy/default/") {
		t.Errorf("args = %q, missing proxy registry", joined)
	}
}

func TestPrepareFreezesInstallAfterValueOption(t *testing.T) {
	prepared, err := (Manager{}).Prepare("pnpm", []string{"--store-dir", "/tmp/store", "install"}, "http://proxy/default/", nil)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !strings.Contains(strings.Join(prepared.Args, " "), "--frozen-lockfile") {
		t.Errorf("args = %v, want frozen lockfile", prepared.Args)
	}
}
