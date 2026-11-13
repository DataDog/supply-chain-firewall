// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"os"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"
)

var poetryRepositoryEnvironment = regexp.MustCompile(`^POETRY_REPOSITORIES_([A-Z_]+)_URL$`)

// configuredRepositories mirrors Config.get("repositories"): an environment
// repository map, when present, replaces the file-configured map. Source hints
// remain separate because these URLs do not change Poetry's package search.
func (s poetrySettings) configuredRepositories() []poetrySource {
	var environment []poetrySource
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if match := poetryRepositoryEnvironment.FindStringSubmatch(key); match != nil {
			name := strings.ReplaceAll(strings.ToLower(match[1]), "_", "-")
			value, _ = s.process(value, 0).(string)
			environment = append(environment, poetrySource{Name: name, URL: value})
		}
	}
	if len(environment) > 0 {
		return environment
	}
	var repositories []poetrySource
	for _, name := range s.repositoryOrder {
		if address, ok := s.get("repositories", name, "url").(string); ok {
			repositories = append(repositories, poetrySource{Name: name, URL: address})
		}
	}
	return repositories
}

// Equal path matches are resolved by insertion order in Poetry's dictionaries.
// Capture that order with the TOML parser, including dotted and inline tables;
// iterating the decoded Go map would choose trust nondeterministically.
func poetryRepositoryNames(data []byte) []string {
	var names, table []string
	seen := map[string]bool{}
	add := func(path []string) {
		if len(path) > 1 && path[0] == "repositories" && !seen[path[1]] {
			seen[path[1]] = true
			names = append(names, path[1])
		}
	}
	keys := func(node *unstable.Node) []string {
		var path []string
		iterator := node.Key()
		for iterator.Next() {
			path = append(path, string(iterator.Node().Data))
		}
		return path
	}
	var inline func([]string, *unstable.Node)
	inline = func(path []string, value *unstable.Node) {
		add(path)
		if len(path) == 1 && path[0] == "repositories" && value.Kind == unstable.InlineTable {
			children := value.Children()
			for children.Next() {
				child := children.Node()
				inline(append(append([]string{}, path...), keys(child)...), child.Value())
			}
		}
	}
	var parser unstable.Parser
	parser.Reset(data) // The document was already validated by toml.Unmarshal.
	for parser.NextExpression() {
		node := parser.Expression()
		switch node.Kind {
		case unstable.Table, unstable.ArrayTable:
			table = keys(node)
			add(table)
		case unstable.KeyValue:
			path := append(append([]string{}, table...), keys(node)...)
			inline(path, node.Value())
		}
	}
	return names
}
