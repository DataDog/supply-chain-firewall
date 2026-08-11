// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Version is a major.minor.patch version, sufficient for gating features
// on a package manager's version without pulling in a full SemVer/PEP 440
// parser (e.g. it has no notion of pre-release or build metadata).
type Version struct {
	Major, Minor, Patch int
}

func (v Version) LessThan(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion parses a "<major>.<minor>[.<patch>]" version string (e.g.
// "24.0", "24.0.1", or "24.0.1rc1"), ignoring any non-whitespace remainder
// attached directly to the patch component. Patch defaults to 0 when
// absent. The input must not contain whitespace: a version token is
// expected to already be isolated from surrounding text by the caller.
func ParseVersion(s string) (Version, error) {
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return Version{}, fmt.Errorf("malformed version %q: contains whitespace", s)
	}

	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return Version{}, fmt.Errorf("malformed version %q", s)
	}

	major, err := parseVersionComponent(s, parts[0])
	if err != nil {
		return Version{}, err
	}
	minor, err := parseVersionComponent(s, parts[1])
	if err != nil {
		return Version{}, err
	}

	patch := 0
	if len(parts) == 3 {
		if strings.HasPrefix(parts[2], "-") {
			return Version{}, fmt.Errorf("malformed version %q: negative version component %q", s, parts[2])
		}

		leadingDigits := parts[2]
		if end := strings.IndexFunc(leadingDigits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
			leadingDigits = leadingDigits[:end]
		}
		if leadingDigits != "" {
			if patch, err = parseVersionComponent(s, leadingDigits); err != nil {
				return Version{}, err
			}
		}
	}

	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// parseVersionComponent parses a single non-negative numeric version
// component, wrapping any error with the full original version string for
// context.
func parseVersionComponent(whole, component string) (int, error) {
	n, err := strconv.Atoi(component)
	if err != nil {
		return 0, fmt.Errorf("malformed version %q: %w", whole, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("malformed version %q: negative version component %q", whole, component)
	}
	return n, nil
}
