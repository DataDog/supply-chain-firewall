// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"strings"
	"testing"
)

func TestParseClassic(t *testing.T) {
	registry, named, err := parseClassic([]byte(
		"{\"type\":\"info\",\"data\":\"yarn config\"}\n" +
			"{\"type\":\"inspect\",\"data\":{\"registry\":\"https://registry.example\"}}\n" +
			"{\"type\":\"inspect\",\"data\":{\"@private:registry\":\"https://private.example\"}}\n",
	))
	if err != nil {
		t.Fatalf("parseClassic() error = %v", err)
	}
	if got := registry.String(); got != "https://registry.example/" {
		t.Errorf("registry = %q", got)
	}
	if got := named["@private"].String(); got != "https://private.example/" {
		t.Errorf("scope = %q", got)
	}
}

func TestPrepareModernPreservesScopeAuthentication(t *testing.T) {
	manager := &Manager{
		modern: true,
		modernScopes: map[string]map[string]any{
			"private": {"npmAuthToken": "secret", "npmAlwaysAuth": true},
		},
	}
	prepared, err := manager.Prepare("yarn", []string{"install"}, "http://proxy/default/", map[string]string{"@private": "http://proxy/private/"})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	environment := strings.Join(prepared.Env, "\n")
	if !strings.Contains(environment, `"npmAuthToken":"secret"`) || !strings.Contains(environment, `"npmAlwaysAuth":true`) {
		t.Fatalf("YARN_NPM_SCOPES did not preserve authentication: %s", environment)
	}
	if !strings.Contains(environment, `"npmRegistryServer":"http://proxy/private/"`) {
		t.Fatalf("YARN_NPM_SCOPES did not replace registry: %s", environment)
	}
}
