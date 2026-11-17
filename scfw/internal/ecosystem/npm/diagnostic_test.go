// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"net/url"
	"testing"
)

func TestDiagnosticPackumentEligibilityDoesNotChangeEnforcement(t *testing.T) {
	classifier, err := NewClassifier(ClassifierOptions{RegistryURLs: []string{"https://private.example/npm/"}})
	if err != nil {
		t.Fatal(err)
	}
	packument := []byte(readNpmJSONFixture(t, "packument/left-pad"))
	for _, test := range []struct {
		url               string
		publication, want bool
	}{
		{"https://private.example/npm/left-pad", false, true},
		{"https://private.example/npm/other-package", false, false},
		{"https://unrelated.example/left-pad", false, false},
		{"https://private.example/npm/-/v1/search", false, false},
		{"https://private.example/npm/left-pad/-/left-pad-1.3.0.tgz", false, false},
		{"https://redirect.example/packument", true, true},
	} {
		t.Run(test.url, func(t *testing.T) {
			parsed, err := url.Parse(test.url)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := classifier.Classify(parsed)
			if got := classifier.DiagnosticMetadata(*parsed, packument, test.publication); got != test.want {
				t.Fatalf("metadata eligibility=%t want %t", got, test.want)
			}
			after, _ := classifier.Classify(parsed)
			if before != after {
				t.Fatal("diagnostics changed enforcement classification")
			}
			if test.url == "https://private.example/npm/left-pad" && before != RequestUnrelated {
				t.Fatal("test no longer covers ordinary unrelated-classified packument")
			}
		})
	}
}
