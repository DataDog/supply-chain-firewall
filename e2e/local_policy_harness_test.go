//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import "testing"

func TestHarnessLocalPolicyEvidence(t *testing.T) {
	var fixtures map[string][]policyRecord
	if err := readJSON("testdata/local_policy/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	options := localPolicyOptions{outcome: "WARN", findings: map[string]string{"exact-warning": "WARNING"}}
	c := candidate{Ecosystem: "PyPI", Project: "package", Version: "1.0"}
	cell := cell{Manager: "pip", Executable: "/pip"}
	for name, records := range fixtures {
		t.Run(name, func(t *testing.T) {
			err := assertLocalPolicy(records, c, cell, options, "BLOCK", "pip install package==1.0")
			if (err == nil) != (name == "warning-block") {
				t.Fatalf("policy evidence validation: %v", err)
			}
		})
	}
	if err := assertLocalPolicy(nil, c, cell, options, "BLOCK", "pip install package==1.0"); err == nil {
		t.Fatal("accepted a missing report")
	}
}
