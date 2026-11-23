// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"path/filepath"
	"strings"
)

// maxBraceExpansions bounds the work of expanding a pattern, which comes from a
// project's package.json and multiplies with every group.
const maxBraceExpansions = 10000

// ExpandBraces expands the first {a,b} group of a glob, recursively; a group
// without a comma, or an unbalanced one, stays literal. A pattern that would
// take more than maxBraceExpansions steps stays literal as a whole.
func ExpandBraces(pattern string) []string {
	budget := maxBraceExpansions
	if expanded := expandBracesWithin(pattern, &budget); budget >= 0 {
		return expanded
	}
	return []string{pattern}
}

func expandBracesWithin(pattern string, budget *int) []string {
	if *budget--; *budget < 0 {
		return nil
	}
	open := strings.Index(pattern, "{")
	if open < 0 {
		return []string{pattern}
	}
	depth, start := 0, open+1
	var options []string
	for index := open; index < len(pattern); index++ {
		switch pattern[index] {
		case '{':
			depth++
		case ',':
			if depth == 1 {
				options = append(options, pattern[start:index])
				start = index + 1
			}
		case '}':
			depth--
			if depth > 0 {
				continue
			}
			options = append(options, pattern[start:index])
			if len(options) < 2 {
				return []string{pattern}
			}
			var expanded []string
			for _, option := range options {
				if *budget < 0 {
					break
				}
				expanded = append(expanded, expandBracesWithin(pattern[:open]+option+pattern[index+1:], budget)...)
			}
			return expanded
		}
	}
	return []string{pattern}
}

// MatchSegment matches one glob segment against one path segment: as in glob,
// wildcards skip names that start with a dot unless the pattern segment starts
// with one.
func MatchSegment(pattern, name string) bool {
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") {
		return false
	}
	// Glob negates a class with "!", filepath.Match with "^".
	matched, err := filepath.Match(strings.ReplaceAll(pattern, "[!", "[^"), name)
	return err == nil && matched
}
