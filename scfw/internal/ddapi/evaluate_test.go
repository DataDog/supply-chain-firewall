// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestPostScfwPolicyEvaluateRequest_MarshalsToExpectedShape(t *testing.T) {
	payload := postScfwPolicyEvaluateRequest{
		Data: postScfwPolicyEvaluateRequestData{
			Type: "scfw-policy-evaluate-request",
			ID:   "d0b65b48-fafe-42cb-8016-d17333e6a72c",
			Attributes: postScfwPolicyEvaluateRequestAttributes{
				Packages: []pm.Package{
					{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.17.0"},
				},
				IsInteractive: true,
			},
		},
	}

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() returned unexpected error: %v", err)
	}

	want := `{"data":{"type":"scfw-policy-evaluate-request","id":"d0b65b48-fafe-42cb-8016-d17333e6a72c",` +
		`"attributes":{"packages":[{"ecosystem":"PyPI","package_name":"six","package_version":"1.17.0"}],` +
		`"is_interactive":true}}}`
	if string(got) != want {
		t.Fatalf("json.Marshal() = %s, want %s", got, want)
	}
}

func TestPostScfwPolicyEvaluateResponse_UnmarshalsRealSample(t *testing.T) {
	// Captured from a real /evaluate response via the DEBUG log added for this endpoint.
	sample := `{"data":{"id":"7f18eaa7-4c74-4475-b217-d0146480e1b3","type":"scfw-policy-evaluate-response",` +
		`"attributes":{"outcome":"ALLOW","results":[` +
		`{"ecosystem":"PyPI","package_name":"python-dateutil","package_version":"2.9.0.post0","outcome":"ALLOW"},` +
		`{"ecosystem":"PyPI","package_name":"urllib3","package_version":"2.7.0","outcome":"ALLOW"}]}}}`

	var got postScfwPolicyEvaluateResponse
	if err := json.Unmarshal([]byte(sample), &got); err != nil {
		t.Fatalf("json.Unmarshal() returned unexpected error: %v", err)
	}

	if got.Data.ID != "7f18eaa7-4c74-4475-b217-d0146480e1b3" {
		t.Errorf("Data.ID = %q, want %q", got.Data.ID, "7f18eaa7-4c74-4475-b217-d0146480e1b3")
	}
	if got.Data.Attributes.Outcome != OutcomeAllow {
		t.Errorf("Data.Attributes.Outcome = %q, want %q", got.Data.Attributes.Outcome, OutcomeAllow)
	}
	if len(got.Data.Attributes.Results) != 2 {
		t.Fatalf("len(Data.Attributes.Results) = %d, want 2", len(got.Data.Attributes.Results))
	}

	first := got.Data.Attributes.Results[0]
	if first.Ecosystem != "PyPI" || first.PackageName != "python-dateutil" ||
		first.PackageVersion != "2.9.0.post0" || first.Outcome != OutcomeAllow {
		t.Errorf("Results[0] = %+v, want ecosystem PyPI, package_name python-dateutil, package_version 2.9.0.post0, outcome ALLOW", first)
	}
}

func TestPackage_RoundTripsThroughJSON(t *testing.T) {
	pkg := pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0", Source: "https://example.com/left-pad"}

	body, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("json.Marshal() returned unexpected error: %v", err)
	}

	var got pm.Package
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal() returned unexpected error: %v", err)
	}
	if got != pkg {
		t.Fatalf("round-tripped Package = %+v, want %+v", got, pkg)
	}
}

func TestPackageEvaluationResult_UnmarshalsMatchedPolicyAndFailures(t *testing.T) {
	sample := `{"ecosystem":"PyPI","package_name":"requests","package_version":"2.31.0","outcome":"BLOCK",` +
		`"matched_policy":[{"type":"org_policy","rule":"no-requests","outcome":"BLOCK"}],` +
		`"failures":[{"verifier":"datadog_policy","error":"advisory-db lookup timed out"}]}`

	var got PackageEvaluationResult
	if err := json.Unmarshal([]byte(sample), &got); err != nil {
		t.Fatalf("json.Unmarshal() returned unexpected error: %v", err)
	}

	if len(got.MatchedPolicy) != 1 {
		t.Fatalf("len(MatchedPolicy) = %d, want 1", len(got.MatchedPolicy))
	}
	wantPolicy := matchedPolicy{Type: "org_policy", Rule: "no-requests", Outcome: OutcomeBlock}
	if got.MatchedPolicy[0] != wantPolicy {
		t.Errorf("MatchedPolicy[0] = %+v, want %+v", got.MatchedPolicy[0], wantPolicy)
	}

	if len(got.Failures) != 1 {
		t.Fatalf("len(Failures) = %d, want 1", len(got.Failures))
	}
	wantFailure := failure{Verifier: "datadog_policy", Error: "advisory-db lookup timed out"}
	if got.Failures[0] != wantFailure {
		t.Errorf("Failures[0] = %+v, want %+v", got.Failures[0], wantFailure)
	}
}
