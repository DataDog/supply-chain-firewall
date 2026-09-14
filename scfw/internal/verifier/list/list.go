// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package list defines a package verifier for user-provided findings lists.
package list

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/home"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/verifier"
)

// The verifier's directory, relative to SCFW's home directory, where findings
// lists are looked up.
const verifierHome = "list_verifier"

// Verifier verifies packages against user-provided findings lists.
type Verifier struct {
	findings findingsMap
}

// findingsMap maps "ecosystem/name" package keys to the findings declared for
// them. Each entry optionally constrains the versions it applies to.
type findingsMap map[string][]findingEntry

// findingEntry is one declared finding for a package, with an optional
// version constraint. A nil Versions entry means all versions.
type findingEntry struct {
	Severity evaluation.Severity
	Text     string
	Versions []string
}

// New returns a Verifier initialized from the findings lists found in the
// list_verifier directory of SCFW's home directory. Files that fail to parse
// are skipped with a warning.
func New() Verifier {
	dir := home.Dir()
	if dir == "" {
		return Verifier{findings: findingsMap{}}
	}
	listsHome := filepath.Join(dir, verifierHome)

	findings := findingsMap{}
	paths, err := filepath.Glob(filepath.Join(listsHome, "*.yml"))
	if err != nil {
		slog.Warn("Failed to discover findings lists", "error", err)
		return Verifier{findings: findings}
	}
	if more, err := filepath.Glob(filepath.Join(listsHome, "*.yaml")); err == nil {
		paths = append(paths, more...)
	}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		entries, err := readFindingsList(path)
		if err != nil {
			slog.Warn("Failed to import findings list", "file", path, "error", err)
			continue
		}
		for key, list := range entries {
			findings[key] = append(findings[key], list...)
		}
	}
	return Verifier{findings: findings}
}

// findingsList is the on-disk findings-list format.
type findingsList struct {
	Findings []struct {
		Severity string `yaml:"severity"`
		Finding  string `yaml:"finding"`
		Packages []struct {
			Ecosystem string   `yaml:"ecosystem"`
			Name      string   `yaml:"name"`
			Versions  []string `yaml:"versions"`
		} `yaml:"packages"`
	} `yaml:"findings"`
}

// readFindingsList parses a single findings-list file.
func readFindingsList(path string) (findingsMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read findings list: %w", err)
	}
	var list findingsList
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("failed to parse findings list: %w", err)
	}

	entries := findingsMap{}
	for _, finding := range list.Findings {
		severity, err := parseSeverity(finding.Severity)
		if err != nil {
			return nil, err
		}
		if finding.Finding == "" {
			return nil, fmt.Errorf("empty finding text")
		}
		for _, pkg := range finding.Packages {
			if pkg.Ecosystem == "" || pkg.Name == "" {
				return nil, fmt.Errorf("findings list entries require an ecosystem and package name")
			}
			eco, err := parseEcosystem(pkg.Ecosystem)
			if err != nil {
				return nil, err
			}
			key := packageKey(eco, pkg.Name)
			entries[key] = append(entries[key], findingEntry{
				Severity: severity,
				Text:     finding.Finding,
				Versions: pkg.Versions,
			})
		}
	}
	return entries, nil
}

// Name returns the verifier's name.
func (Verifier) Name() string {
	return "FindingsListVerifier"
}

// Verify returns the findings declared for the given package in the
// user-provided findings lists.
func (v Verifier) Verify(_ context.Context, pkg pm.Package) ([]evaluation.Finding, error) {
	if pkg.Ecosystem != ecosystem.NPM && pkg.Ecosystem != ecosystem.PYPI {
		return nil, fmt.Errorf("package ecosystem %s is not supported", pkg.Ecosystem)
	}
	if pkg.Source != "" && !ecosystem.HasRegistrySource(pkg.Ecosystem, pkg.Source) {
		return nil, fmt.Errorf("cannot verify package with non-%s registry source", pkg.Ecosystem)
	}

	key := packageKey(pkg.Ecosystem, pkg.Name)
	var findings []evaluation.Finding
	for _, entry := range v.findings[key] {
		if len(entry.Versions) > 0 && !containsVersion(entry.Versions, pkg.Version) {
			continue
		}
		findings = append(findings, evaluation.Finding{
			Verifier: v.Name(),
			Severity: entry.Severity,
			Text:     entry.Text,
		})
	}
	return findings, nil
}

func parseSeverity(value string) (evaluation.Severity, error) {
	switch strings.ToUpper(value) {
	case string(evaluation.SeverityCritical):
		return evaluation.SeverityCritical, nil
	case string(evaluation.SeverityWarning):
		return evaluation.SeverityWarning, nil
	default:
		return "", fmt.Errorf("invalid finding severity: %q", value)
	}
}

func parseEcosystem(value string) (ecosystem.Ecosystem, error) {
	switch {
	case strings.EqualFold(value, string(ecosystem.NPM)):
		return ecosystem.NPM, nil
	case strings.EqualFold(value, string(ecosystem.PYPI)):
		return ecosystem.PYPI, nil
	default:
		return "", fmt.Errorf("invalid package ecosystem: %q", value)
	}
}

func packageKey(eco ecosystem.Ecosystem, name string) string {
	return fmt.Sprintf("%s/%s", eco, name)
}

// containsVersion reports whether versions contains version.
func containsVersion(versions []string, version string) bool {
	for _, v := range versions {
		if v == "*" || v == version {
			return true
		}
	}
	return false
}

// Verifier implements the verifier.Verifier interface.
var _ verifier.Verifier = Verifier{}
