//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHarnessNPMDiscovery(t *testing.T) {
	var fixtures map[string]npmMetadata
	if err := readJSON("testdata/npm_baseline/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	version, selected, err := selectNPMRelease(fixtures["valid"], "14.21.3", now)
	if err != nil || version != "1.0.0" || !selected.UploadedAt.Equal(now.Add(-9*24*time.Hour)) {
		t.Fatalf("selected %s %+v: %v; must use time[version], not latest/modified", version, selected, err)
	}
	for _, name := range []string{"missing_time", "runtime_dependency", "install_script", "bad_integrity", "foreign_tarball", "deprecated"} {
		if _, _, err := selectNPMRelease(fixtures[name], "14.21.3", now); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if _, _, err := selectNPMRelease(fixtures["valid"], "10.0.0", now); err == nil {
		t.Fatal("selected incompatible Node engine")
	}
	c := candidate{Ecosystem: "npm", Project: "fixture-leaf", Version: version, Artifacts: []artifact{selected}}
	if err := matchNPMCandidate(fixtures["valid"], c); err != nil {
		t.Fatal(err)
	}
	if err := matchNPMCandidate(fixtures["changed_time"], c); err == nil {
		t.Fatal("accepted changed publication date")
	}
	c.Artifacts[0].Integrity = "sha512-different"
	if err := matchNPMCandidate(fixtures["valid"], c); err == nil {
		t.Fatal("accepted changed artifact integrity")
	}
}

type npmRelease struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Deprecated           string            `json:"deprecated"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Scripts              map[string]string `json:"scripts"`
	Engines              struct {
		Node string `json:"node"`
	} `json:"engines"`
	Dist struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
}
type npmMetadata struct {
	Name     string                `json:"name"`
	Time     map[string]string     `json:"time"`
	Versions map[string]npmRelease `json:"versions"`
}

func init() {
	for _, key := range []string{"npm-old", "npm-old-scoped"} {
		discoverers[key] = func(ctx context.Context, c cell, output string) (candidate, error) {
			return discoverNPMOld(ctx, c, output, key)
		}
		revalidators[key] = revalidateNPM
	}
}

func discoverNPMOld(ctx context.Context, c cell, output, key string) (candidate, error) {
	var pool map[string][]string
	if err := readJSON("testdata/npm_candidates.json", &pool); err != nil {
		return candidate{}, err
	}
	now := time.Now().UTC()
	var rejected []string
	var evidence []metadataEvidence
	for _, name := range pool[key] {
		var metadata npmMetadata
		snapshot, err := fetchJSON(ctx, npmMetadataURL(name), filepath.Join(output, strings.ReplaceAll(name, "/", "-")+".json"), &metadata)
		if err != nil {
			return candidate{}, err
		}
		evidence = append(evidence, snapshot)
		if metadata.Name != name {
			return candidate{}, fmt.Errorf("registry project identity mismatch for %s", name)
		}
		version, download, err := selectNPMRelease(metadata, c.RuntimeVersion, now)
		if err != nil {
			rejected = append(rejected, name+": "+err.Error())
			continue
		}
		module := name
		if strings.HasPrefix(name, "@types/") {
			module = ""
		}
		return candidate{Ecosystem: "npm", Project: name, Version: version, Property: "old-leaf", Module: module, Metadata: evidence, Artifacts: []artifact{download}, ObservedAt: now, LatestValidStart: now.Add(24 * time.Hour), Constraints: []string{"Node " + c.RuntimeVersion, "no runtime dependencies or installation lifecycle scripts", "publication older than48h"}, Evidence: append(rejected, "selected newest eligible time[version]; never reroll after SCFW execution")}, nil
	}
	return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no eligible public npm candidate: %v", rejected))
}

func npmMetadataURL(name string) string { return "https://registry.npmjs.org/" + url.PathEscape(name) }

func selectNPMRelease(metadata npmMetadata, runtime string, now time.Time) (string, artifact, error) {
	type choice struct {
		version  string
		download artifact
	}
	var choices []choice
	for version, release := range metadata.Versions {
		download, err := npmArtifact(metadata, version)
		if err != nil || download.UploadedAt.After(now.Add(-48*time.Hour)) || !compatibleNodeFloor(release.Engines.Node, runtime) {
			continue
		}
		choices = append(choices, choice{version, download})
	}
	if len(choices) == 0 {
		return "", artifact{}, fmt.Errorf("no stable, dependency-free public tarball older than48h compatible with Node%s", runtime)
	}
	slices.SortFunc(choices, func(a, b choice) int {
		if order := b.download.UploadedAt.Compare(a.download.UploadedAt); order != 0 {
			return order
		}
		return strings.Compare(a.version, b.version)
	})
	return choices[0].version, choices[0].download, nil
}

func npmArtifact(metadata npmMetadata, version string) (artifact, error) {
	release, found := metadata.Versions[version]
	validName := regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	if !found || !validName.MatchString(metadata.Name) || release.Name != metadata.Name || release.Version != version || !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		return artifact{}, fmt.Errorf("missing or invalid npm release identity")
	}
	if release.Deprecated != "" || len(release.Dependencies)+len(release.OptionalDependencies)+len(release.PeerDependencies) > 0 {
		return artifact{}, fmt.Errorf("release is deprecated or has runtime dependencies")
	}
	for _, event := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if release.Scripts[event] != "" {
			return artifact{}, fmt.Errorf("release has %s lifecycle script", event)
		}
	}
	published, err := time.Parse(time.RFC3339Nano, metadata.Time[version])
	if err != nil || published.IsZero() {
		return artifact{}, fmt.Errorf("missing or invalid time[%s]", version)
	}
	target, err := url.Parse(release.Dist.Tarball)
	if err != nil || target.Scheme != "https" || target.Host != "registry.npmjs.org" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || !strings.HasSuffix(target.Path, ".tgz") {
		return artifact{}, fmt.Errorf("release is not a public npm tarball")
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(release.Dist.Integrity, "sha512-"))
	if err != nil || !strings.HasPrefix(release.Dist.Integrity, "sha512-") || len(digest) != 64 {
		return artifact{}, fmt.Errorf("missing or invalid SHA512 integrity")
	}
	return artifact{Name: filepath.Base(target.Path), URL: release.Dist.Tarball, Integrity: release.Dist.Integrity, UploadedAt: published}, nil
}

// The maintained candidate pool uses simple Node lower bounds. Unknown ranges
// are rejected; this helper does not reproduce npm's general semver resolver.
func compatibleNodeFloor(spec, version string) bool {
	if spec == "" {
		return true
	}
	match := regexp.MustCompile(`^>=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$`).FindStringSubmatch(spec)
	actual := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if match == nil || len(actual) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		minimum := 0
		if match[i+1] != "" {
			minimum, _ = strconv.Atoi(match[i+1])
		}
		value, err := strconv.Atoi(actual[i])
		if err != nil {
			return false
		}
		if value != minimum {
			return value > minimum
		}
	}
	return true
}

func matchNPMCandidate(metadata npmMetadata, c candidate) error {
	if c.Ecosystem != "npm" || c.Project != metadata.Name || len(c.Artifacts) != 1 {
		return fmt.Errorf("npm candidate identity mismatch")
	}
	current, err := npmArtifact(metadata, c.Version)
	if err != nil {
		return err
	}
	expected := c.Artifacts[0]
	if current.Name != expected.Name || current.URL != expected.URL || current.Integrity != expected.Integrity || !current.UploadedAt.Equal(expected.UploadedAt) {
		return fmt.Errorf("discovered npm artifact or publication date changed")
	}
	return nil
}
func revalidateNPM(ctx context.Context, c candidate, output string) error {
	var metadata npmMetadata
	_, err := fetchJSON(ctx, npmMetadataURL(c.Project), filepath.Join(output, "npm.json"), &metadata)
	if err != nil {
		return err
	}
	return classified("PRECONDITION_UNAVAILABLE", matchNPMCandidate(metadata, c))
}

func TestHarnessNPMAliasCapability(t *testing.T) {
	c := cell{ID: "npm7", Manager: "npm", ManagerVersion: "7.0.0", Modes: []string{"resolution", "proxy"}, Suites: []string{"npm-baseline"}}
	cases, err := selectCases(c, []string{"npm-baseline"})
	if err != nil {
		t.Fatal(err)
	}
	unavailable := 0
	for _, item := range cases {
		if item.NotApplicable != "" {
			unavailable++
			if !strings.Contains(item.Variant, "-isntall-") || !strings.Contains(item.NotApplicable, "npm-alias-isntall-install") {
				t.Fatalf("unexpected N/A: %+v", item)
			}
		}
	}
	if unavailable != 4 {
		t.Fatalf("N/A=%d, want four native isntall alias variants", unavailable)
	}
	c.Capabilities = []string{"npm-alias-isntall-install"}
	cases, err = selectCases(c, []string{"npm-baseline"})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		if item.NotApplicable != "" {
			t.Fatalf("verified install alias is N/A: %+v", item)
		}
	}
}
