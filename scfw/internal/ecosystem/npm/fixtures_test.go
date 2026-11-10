// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readNpmFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func readNpmJSONFixture(t *testing.T, name string) string {
	t.Helper()
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readNpmFixture(t, "responses.json")), &fixtures); err != nil {
		t.Fatalf("read JSON fixtures: %v", err)
	}
	data, found := fixtures[name]
	if !found {
		t.Fatalf("unknown JSON fixture %q", name)
	}
	return string(data)
}
