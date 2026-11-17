// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiagnosticVersionProbeIsBounded(t *testing.T) {
	fixture, err := os.ReadFile("testdata/diagnostic-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "uv")
	if err := os.WriteFile(executable, fixture, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, version string }{{"normal", "0.13.4"}, {"verbose", "0.13.4"}, {"descendants", "unknown"}} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SCFW_TEST_VERSION_CASE", test.name)
			start := time.Now()
			info := (UV{executable: executable}).DiagnosticInfo(context.Background(), nil)
			if info.Version != test.version {
				t.Fatalf("version = %q, want %q", info.Version, test.version)
			}
			if time.Since(start) > 4*time.Second {
				t.Fatal("version probe exceeded its subprocess deadline")
			}
		})
	}
}
