// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxManifestBytes = 1 << 20
const maxJSONDepth = 64
const maxJSONToken = 1 << 20

// Difference retains values for callers; diagnostics must render paths only.
type Difference struct {
	Path, Kind         string
	Registry, Artifact any
}

// ArchiveFacts contains bounded facts, never extracted archive contents.
type ArchiveFacts struct{ BindingGyp, Shrinkwrap bool }

// parseObject rejects ambiguous JSON rather than accepting encoding/json's
// duplicate-key, invalid-Unicode, or case-insensitive struct behavior.
func parseObject(data []byte, limit int64) (map[string]any, error) {
	if int64(len(data)) > limit {
		return nil, errInspectionLimit
	}
	if !utf8.Valid(data) {
		return nil, errors.New("invalid or oversized JSON")
	}
	// encoding/json replaces unpaired UTF-16 escapes; reject these explicitly.
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		i++
		for ; i < len(data) && data[i] != '"'; i++ {
			if data[i] != '\\' {
				continue
			}
			i++
			if i >= len(data) {
				break
			}
			if data[i] == 'u' && i+4 < len(data) {
				n, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
				if e == nil && n >= 0xd800 && n <= 0xdfff {
					if n >= 0xdc00 || i+10 >= len(data) || string(data[i+5:i+7]) != "\\u" {
						return nil, errors.New("invalid JSON Unicode")
					}
					low, e := strconv.ParseUint(string(data[i+7:i+11]), 16, 16)
					if e != nil || low < 0xdc00 || low > 0xdfff {
						return nil, errors.New("invalid JSON Unicode")
					}
					i += 6
				}
				i += 4
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := readJSONValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil, errors.New("JSON object required")
	}
	return m, nil
}
func readJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errInspectionLimit
	}
	t, err := d.Token()
	if err != nil {
		return nil, errors.New("invalid JSON")
	}
	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, errors.New("invalid JSON key")
				}
				key, ok := k.(string)
				if !ok || len(key) > maxJSONToken {
					return nil, errors.New("invalid JSON key")
				}
				if _, ok = m[key]; ok {
					return nil, errors.New("duplicate JSON key")
				}
				value, e := readJSONValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = value
			}
			if _, err = d.Token(); err != nil {
				return nil, errors.New("invalid JSON object")
			}
			return m, nil
		}
		if v == '[' {
			a := []any{}
			for d.More() {
				x, e := readJSONValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			if _, err = d.Token(); err != nil {
				return nil, errors.New("invalid JSON array")
			}
			return a, nil
		}
		return nil, errors.New("invalid JSON delimiter")
	case string:
		if len(v) > maxJSONToken {
			return nil, errInspectionLimit
		}
	case json.Number:
		if err := validateNumber(v); err != nil {
			return nil, err
		}
	}
	return t, nil
}
func validateNumber(n json.Number) error {
	s := string(n)
	if len(s) > 1024 {
		return errInspectionLimit
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil || e > 4096 || e < -4096 {
			return errInspectionLimit
		}
	}
	return nil
}
func numberValue(n json.Number) (*big.Rat, error) {
	if e := validateNumber(n); e != nil {
		return nil, e
	}
	s := string(n)
	v, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("invalid JSON number")
	}
	return v, nil
}

// CompareManifests compares explicitly selected fields in both directions after
// the publication rules in manifest_normalize.go. Input maps are never shared.
func CompareManifests(name, version string, registry, artifact []byte, facts ArchiveFacts) ([]Difference, error) {
	a, e := parseObject(registry, maxManifestBytes)
	if e != nil {
		return nil, e
	}
	b, e := parseObject(artifact, maxManifestBytes)
	if e != nil {
		return nil, e
	}
	diffs := []Difference{}
	for _, x := range []struct {
		m    map[string]any
		side string
	}{{a, "registry"}, {b, "artifact"}} {
		for k, want := range map[string]string{"name": name, "version": version} {
			if x.m[k] != want {
				diffs = append(diffs, Difference{Path: "/" + k, Kind: x.side + " identity"})
			}
		}
	}
	if id, ok := a["_id"]; ok && id != name+"@"+version {
		diffs = append(diffs, Difference{Path: "/_id", Kind: "registry identity"})
	}
	a, b = comparisonManifest(a), comparisonManifest(b)
	normalizeManifest(a, facts)
	normalizeManifest(b, facts)
	validateDerived(a, facts, &diffs, "registry")
	validateDerived(b, facts, &diffs, "artifact")
	diffJSON("", a, b, &diffs)
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Path == diffs[j].Path {
			return diffs[i].Kind < diffs[j].Kind
		}
		return diffs[i].Path < diffs[j].Path
	})
	return diffs, nil
}
func diffJSON(p string, a, b any, d *[]Difference) {
	if am, ok := a.(map[string]any); ok {
		if bm, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range bm {
				keys[k] = true
			}
			for k := range keys {
				av, ao := am[k]
				bv, bo := bm[k]
				q := p + "/" + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
				if !ao {
					*d = append(*d, Difference{q, "artifact-only", nil, bv})
				} else if !bo {
					*d = append(*d, Difference{q, "registry-only", av, nil})
				} else {
					diffJSON(q, av, bv, d)
				}
			}
			return
		}
	}
	if aa, ok := a.([]any); ok {
		if bb, ok := b.([]any); ok && len(aa) == len(bb) {
			for i := range aa {
				diffJSON(p+"/"+strconv.Itoa(i), aa[i], bb[i], d)
			}
			return
		}
	}
	equal := false
	if an, ok := a.(json.Number); ok {
		if bn, ok := b.(json.Number); ok {
			if an == bn {
				equal = true
			} else {
				av, _ := numberValue(an)
				bv, _ := numberValue(bn)
				equal = av.Cmp(bv) == 0
			}
		}
	} else {
		switch av := a.(type) {
		case nil:
			equal = b == nil
		case string:
			bv, ok := b.(string)
			equal = ok && av == bv
		case bool:
			bv, ok := b.(bool)
			equal = ok && av == bv
		}
	}
	if !equal {
		*d = append(*d, Difference{p, "unequal", a, b})
	}
}

// DifferenceSummary lists unique differing field paths, separated by commas.
// It never emits values or unescaped user-controlled text.
func DifferenceSummary(d []Difference) string {
	fields := make([]string, 0, len(d))
	for _, difference := range d {
		fields = append(fields, difference.Path)
	}
	sort.Strings(fields)
	fields = slices.Compact(fields)
	var s strings.Builder
	for i, p := range fields {
		if i == 12 {
			fmt.Fprintf(&s, ", ... (%d additional fields)", len(fields)-i)
			break
		}
		if i > 0 {
			s.WriteString(", ")
		}
		if len(p) > 160 {
			p = p[:160] + "..."
		}
		s.WriteString(strconv.QuoteToASCII(p))
	}
	return s.String()
}

func validateDerived(m map[string]any, facts ArchiveFacts, diffs *[]Difference, side string) {
	scripts, _ := m["scripts"].(map[string]any)
	has := false
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if value, ok := scripts[k].(string); ok && value != "" {
			has = true
		}
	}
	for k, want := range map[string]bool{"hasInstallScript": has, "_hasShrinkwrap": facts.Shrinkwrap} {
		if v, ok := m[k]; ok && v != want {
			*diffs = append(*diffs, Difference{Path: "/" + k, Kind: side + " indicator disagrees with archive"})
		}
	}
}
