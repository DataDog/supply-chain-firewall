// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import "testing"

func TestParseConfigList(t *testing.T) {
	values := parseConfigList("global.index-url='https://index.example/simple'\nglobal.extra-index-url='https://extra.example/simple'\n")
	if got := values["global.index-url"]; got != "https://index.example/simple" {
		t.Errorf("index-url = %q", got)
	}
	if got := values["global.extra-index-url"]; got != "https://extra.example/simple" {
		t.Errorf("extra-index-url = %q", got)
	}
}
