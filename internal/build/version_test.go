// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package build

import "testing"

func TestGetVersion_Override(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{name: "release version", version: "1.2.3"},
		{name: "pre-release version", version: "1.2.3-rc.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := Version
			t.Cleanup(func() { Version = original })

			Version = tt.version

			if got := GetVersion(); got != tt.version {
				t.Errorf("GetVersion() = %q, want %q", got, tt.version)
			}
		})
	}
}
