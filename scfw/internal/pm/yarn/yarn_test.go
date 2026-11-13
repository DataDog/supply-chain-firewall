// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// fakeYarnVersionEnv makes the test binary act as `yarn --version`.
const fakeYarnVersionEnv = "SCFW_TEST_FAKE_YARN_VERSION"

func TestMain(m *testing.M) {
	if version := os.Getenv(fakeYarnVersionEnv); version != "" {
		fmt.Println(version)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeYarn(t *testing.T, version string) Yarn {
	t.Helper()
	t.Setenv(fakeYarnVersionEnv, version)
	manager, err := NewYarn(context.Background(), "yarn", os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	// Only NewYarn runs the fake; later processes must not inherit it.
	t.Setenv(fakeYarnVersionEnv, "")
	return manager
}

func TestYarnGeneration(t *testing.T) {
	for _, version := range []string{"1.22.22", "1.22.0", "4.18.1", "4.0.2"} {
		if _, err := fakeYarn(t, version).UpstreamProxy(nil); err != nil {
			t.Errorf("%s: %v", version, err)
		}
	}
	for _, version := range []string{"1.21.1", "3.8.7", "2.4.2", "5.0.0", "not-a-version"} {
		if _, err := fakeYarn(t, version).UpstreamProxy(nil); !errors.Is(err, pm.ErrUnsupportedVersion) {
			t.Errorf("%s: error = %v, want ErrUnsupportedVersion", version, err)
		}
	}
	manager, err := NewYarn(context.Background(), "yarn", filepath.Join(t.TempDir(), "missing-yarn"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.UpstreamProxy(nil); !errors.Is(err, pm.ErrUnsupportedVersion) {
		t.Fatalf("missing executable: error = %v, want ErrUnsupportedVersion", err)
	}
}
