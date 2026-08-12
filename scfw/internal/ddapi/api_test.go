// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import "testing"

func TestResolveDdSite_UsesEnvVarWhenSet(t *testing.T) {
	t.Setenv(ddSiteVar, "datadoghq.eu")

	if got := resolveDdSite(); got != "datadoghq.eu" {
		t.Fatalf("resolveDdSite() = %q, want %q", got, "datadoghq.eu")
	}
}

func TestResolveDdSite_DefaultsWhenEnvVarUnset(t *testing.T) {
	t.Setenv(ddSiteVar, "")

	if got := resolveDdSite(); got != ddSiteDefault {
		t.Fatalf("resolveDdSite() = %q, want %q", got, ddSiteDefault)
	}
}
