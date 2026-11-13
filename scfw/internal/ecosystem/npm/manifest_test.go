// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestManifestFixtures(t *testing.T) {
	data, e := os.ReadFile("testdata/responses.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures map[string]json.RawMessage
	if e = json.Unmarshal(data, &fixtures); e != nil {
		t.Fatal(e)
	}
	data = fixtures["manifest-comparison"]
	var cases map[string]struct {
		Registry, Artifact json.RawMessage
		Matched            bool
		Facts              ArchiveFacts
	}
	if e = json.Unmarshal(data, &cases); e != nil {
		t.Fatal(e)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			diff, e := CompareManifests("fixture", "1.0.0", c.Registry, c.Artifact, c.Facts)
			if e != nil {
				t.Fatal(e)
			}
			if (len(diff) == 0) != c.Matched {
				t.Fatalf("differences %s, want matched=%v", DifferenceSummary(diff), c.Matched)
			}
		})
	}
}
func TestStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":1} {}`, `[]`, `null`, `{"x":"\uD800"}`, `{"x":"\uDC00"}`, `{"x":"` + string([]byte{0xff}) + `"}`, `{"x":1e9999999}`, strings.Repeat(`{"x":`, 70) + `0` + strings.Repeat(`}`, 70)} {
		if _, e := parseObject([]byte(raw), maxManifestBytes); e == nil {
			t.Fatalf("accepted ambiguous JSON: %q", raw)
		}
	}
	for _, raw := range []string{`{"x":"\uD83D\uDE00"}`, `{"x":"\\uD800"}`, `{"x":null}`, `{"x":9007199254740993}`} {
		if _, e := parseObject([]byte(raw), maxManifestBytes); e != nil {
			t.Fatalf("rejected valid JSON %q: %v", raw, e)
		}
	}
}
func TestExactNumbersAndSafeDiagnostics(t *testing.T) {
	for _, pair := range []struct {
		a, b  string
		equal bool
	}{{"9007199254740992", "9007199254740993", false}, {"1.0", "1e0", true}, {"0", "-0", true}} {
		a := []byte(`{"name":"fixture","version":"1.0.0","n":` + pair.a + `}`)
		b := []byte(`{"name":"fixture","version":"1.0.0","n":` + pair.b + `}`)
		am, e := parseObject(a, maxManifestBytes)
		if e != nil {
			t.Fatal(e)
		}
		bm, e := parseObject(b, maxManifestBytes)
		if e != nil {
			t.Fatal(e)
		}
		d := []Difference{}
		diffJSON("", am, bm, &d)
		if (len(d) == 0) != pair.equal {
			t.Fatalf("number comparison %v", d)
		}
	}
	d := []Difference{}
	for i := range 20 {
		d = append(d, Difference{Path: "/script\n\x1b" + strings.Repeat("x", i), Kind: "unequal", Registry: "secret", Artifact: "secret"})
	}
	s := DifferenceSummary(d)
	if strings.Contains(s, "secret") || strings.ContainsAny(s, "\n\x1b") || !strings.Contains(s, "8 additional fields") || strings.Contains(s, "unequal") {
		t.Fatal(s)
	}
}

func TestManifestFieldSelection(t *testing.T) {
	var cases map[string]struct {
		Field         string
		First, Second json.RawMessage
		Compared      bool
	}
	if err := json.Unmarshal([]byte(readNpmJSONFixture(t, "manifest-field-selection")), &cases); err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"equal", "changed", "registry-only", "artifact-only"} {
				t.Run(mode, func(t *testing.T) {
					registry := map[string]json.RawMessage{"name": json.RawMessage(`"fixture"`), "version": json.RawMessage(`"1.0.0"`)}
					artifact := map[string]json.RawMessage{"name": json.RawMessage(`"fixture"`), "version": json.RawMessage(`"1.0.0"`)}
					registry[c.Field], artifact[c.Field] = c.First, c.First
					switch mode {
					case "changed":
						artifact[c.Field] = c.Second
					case "registry-only":
						delete(artifact, c.Field)
					case "artifact-only":
						delete(registry, c.Field)
					}
					a, err := json.Marshal(registry)
					if err != nil {
						t.Fatal(err)
					}
					b, err := json.Marshal(artifact)
					if err != nil {
						t.Fatal(err)
					}
					diff, err := CompareManifests("fixture", "1.0.0", a, b, ArchiveFacts{})
					if err != nil {
						t.Fatal(err)
					}
					wantMatch := !c.Compared || mode == "equal"
					if (len(diff) == 0) != wantMatch {
						t.Fatalf("differences %s, want matched=%v", DifferenceSummary(diff), wantMatch)
					}
				})
			}
		})
	}
}

func TestDifferenceSummaryUniqueFields(t *testing.T) {
	differences := []Difference{
		{Path: "/scripts/install", Kind: "registry identity"},
		{Path: "/dependencies/extra", Kind: "artifact-only"},
		{Path: "/scripts/install", Kind: "unequal"},
	}
	want := `"/dependencies/extra", "/scripts/install"`
	if got := DifferenceSummary(differences); got != want {
		t.Fatalf("difference summary=%q, want %q", got, want)
	}
	if got := DifferenceSummary(nil); got != "" {
		t.Fatalf("empty difference summary=%q", got)
	}
}
