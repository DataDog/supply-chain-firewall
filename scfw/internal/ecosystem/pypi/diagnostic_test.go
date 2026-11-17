// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"net/http"
	"net/url"
	"testing"
)

func TestDiagnosticMetadataRequiresProtocolAndBodyEvidence(t *testing.T) {
	classifier, err := NewRequestClassifier(RequestClassifierOptions{SimpleIndexURLs: []string{"https://index.example/python/"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, url, fixture string
		want               bool
	}{
		{"configured metadata", "https://index.example/python/project/", "metadata/empty-simple", true},
		{"JSON API identity", "https://index.example/api/project", "metadata/legacy-version-info", true},
		{"opaque distribution is not automatically metadata", "https://files.example/opaque", "metadata/cdn-opaque-wheel", false},
		{"validated metadata on a wheel-shaped endpoint", "https://index.example/project-1.0-py3-none-any.whl", "metadata/legacy-version-info", true},
		{"wheel path and JSON MIME alone do not establish metadata", "https://index.example/project-1.0-py3-none-any.whl", "diagnostic/unrelated", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := url.Parse(test.url)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(readPyPIJSONFixture(t, test.fixture))
			if got := classifier.DiagnosticMetadata(*parsed, http.Header{"Content-Type": []string{"application/json"}}, body); got != test.want {
				t.Fatalf("eligibility=%t want=%t", got, test.want)
			}
		})
	}
}
