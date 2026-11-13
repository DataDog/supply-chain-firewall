// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package bun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// fakeBun installs testdata/fake-bun as bun with a bunx symlink beside it.
func fakeBun(t *testing.T, version string) (string, string) {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("testdata", "fake-bun"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bun := filepath.Join(dir, "bun")
	if err := os.WriteFile(bun, script, 0700); err != nil {
		t.Fatal(err)
	}
	bunx := filepath.Join(dir, "bunx")
	if err := os.Symlink(bun, bunx); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCFW_FAKE_BUN_VERSION", version)
	return bun, bunx
}

func TestVersionGating(t *testing.T) {
	for version, supported := range map[string]bool{"1.1.38": false, "1.2.0": true, "1.3.14": true, "1.4.4": true, "2.0.0": false, "nonsense": false} {
		t.Run(version, func(t *testing.T) {
			bun, bunx := fakeBun(t, version)
			for name, executable := range map[string]string{"bun": bun, "bunx": bunx} {
				manager, err := NewBun(context.Background(), name, executable)
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.checkVersion(); (err == nil) != supported || (err != nil && !errors.Is(err, pm.ErrUnsupportedVersion)) {
					t.Fatalf("%s: checkVersion() = %v, want supported=%v", name, err, supported)
				}
			}
		})
	}
}

func TestResolveInstallTargetsRequiresProxyMode(t *testing.T) {
	if _, err := (Bun{}).ResolveInstallTargets(context.Background(), []string{"run", "x"}); err == nil {
		t.Fatal("want an error without proxy mode")
	}
}
