// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"slices"
	"strings"
	"testing"
)

// Groups multiply, and the pattern comes from a project's package.json.
func TestExpandBracesIsBounded(t *testing.T) {
	pattern := strings.Repeat("{a,b}", 20)
	if got := ExpandBraces(pattern); !slices.Equal(got, []string{pattern}) {
		t.Fatalf("ExpandBraces(%q) returned %d patterns", pattern, len(got))
	}
	if got := ExpandBraces(strings.Repeat("{a,b}", 3)); len(got) != 8 {
		t.Fatalf("a small product expanded to %d patterns, want 8", len(got))
	}
}

func TestMatchSegment(t *testing.T) {
	for _, test := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", "a", true},
		{"*", ".hidden", false},
		{".*", ".hidden", true},
		{".hidden", ".hidden", true},
		{"[!b]", "a", true},
		{"[!b]", "b", false},
		{"[", "[", false},
	} {
		if got := MatchSegment(test.pattern, test.name); got != test.want {
			t.Errorf("MatchSegment(%q, %q) = %v, want %v", test.pattern, test.name, got, test.want)
		}
	}
}
