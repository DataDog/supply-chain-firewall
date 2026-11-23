//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const npmAgeWindow = 24 * time.Hour
const npmAgeMargin = 2 * time.Hour // Queue, 3-minute case execution and clock-skew budget.

func init() {
	discoverers["npm-recent"] = discoverNPMRecent
	revalidators["npm-recent"] = revalidateNPMRecent
}

func discoverNPMRecent(ctx context.Context, c cell, output string) (chosen candidate, err error) {
	var pool []string
	if err = readJSON("testdata/age_npm/candidates.json", &pool); err != nil {
		return chosen, err
	}
	var snapshots []metadataEvidence
	var history []string
	defer func() {
		status, reason := "PASS", ""
		if err != nil {
			status, reason = "PRECONDITION_UNAVAILABLE", err.Error()
			if failure, ok := err.(caseFailure); ok {
				status = failure.status
			}
		}
		if saveErr := writeJSON(filepath.Join(output, "search.json"), map[string]any{"status": status, "reason": reason, "metadata": snapshots, "history": history, "selected": chosen}); saveErr != nil {
			err = saveErr
		}
	}()
	if len(pool) == 0 || len(pool) > 8 {
		return chosen, fmt.Errorf("recent npm search requires one to eight maintained candidates")
	}
	for _, name := range pool {
		var metadata npmMetadata
		snapshot, fetchErr := fetchJSON(ctx, npmMetadataURL(name), filepath.Join(output, strings.ReplaceAll(name, "/", "-")+".json"), &metadata)
		snapshots = append(snapshots, snapshot)
		if fetchErr != nil {
			return chosen, fetchErr
		}
		if metadata.Name != name {
			return chosen, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("registry identity mismatch for %s", name))
		}
		now := time.Now().UTC()
		version, download, rejected, selectErr := selectNPMRecent(metadata, c.RuntimeVersion, now)
		history = append(history, rejected...)
		if selectErr != nil {
			continue
		}
		chosen = candidate{Ecosystem: "npm", Project: name, Version: version, Property: "recent-leaf", AgeThresholdHours: 24, ApplicableCells: []string{c.ID}, Metadata: snapshots, Artifacts: []artifact{download}, ObservedAt: now, LatestValidStart: download.UploadedAt.Add(npmAgeWindow - npmAgeMargin), Constraints: []string{"Node " + c.RuntimeVersion, "no runtime dependencies or install lifecycle scripts", "age >=65m and <22h; default24h; explicit1h control"}, Evidence: append(history, "selected newest eligible time[version]; never reroll after SCFW execution")}
		return chosen, nil
	}
	return chosen, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no eligible public npm release in bounded pool; search evidence: %s", filepath.Join(output, "search.json")))
}

func selectNPMRecent(metadata npmMetadata, runtime string, now time.Time) (string, artifact, []string, error) {
	var version string
	var selected artifact
	var rejected []string
	versions := make([]string, 0, len(metadata.Versions))
	for v := range metadata.Versions {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	for _, v := range versions {
		download, err := npmArtifact(metadata, v)
		reason := ""
		switch {
		case err != nil:
			reason = err.Error()
		case !compatibleNodeFloor(metadata.Versions[v].Engines.Node, runtime):
			reason = "incompatible or unsupported Node engine range"
		case !now.Before(download.UploadedAt.Add(npmAgeWindow - npmAgeMargin)):
			reason = "not recent enough for24h threshold plus2h margin"
		case download.UploadedAt.After(now.Add(-65 * time.Minute)):
			reason = "future timestamp or too young for explicit1h control plus5m margin"
		}
		if reason != "" {
			rejected = append(rejected, metadata.Name+"@"+v+": "+reason)
			continue
		}
		if version == "" || download.UploadedAt.After(selected.UploadedAt) {
			version, selected = v, download
		}
	}
	if version == "" {
		return "", artifact{}, rejected, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no eligible recent npm release"))
	}
	return version, selected, rejected, nil
}

func validateNPMRecentCell(c candidate, current cell, now time.Time) error {
	if c.AgeThresholdHours != 24 || !slices.Contains(c.ApplicableCells, current.ID) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("recent manifest threshold or applicable cell differs from this run"))
	}
	return classified("PRECONDITION_UNAVAILABLE", validateCandidate(c, now))
}

func checkNPMRecentInterval(c candidate, start, end time.Time) error {
	if len(c.Artifacts) != 1 || end.Before(start) {
		return fmt.Errorf("invalid recent npm artifact or run interval")
	}
	published := c.Artifacts[0].UploadedAt
	if published.After(start.Add(-65*time.Minute)) || !end.Before(published.Add(npmAgeWindow)) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("recent npm age precondition expired or changed during [%s,%s]; published%s", start, end, published))
	}
	return nil
}

func revalidateNPMRecent(ctx context.Context, c candidate, output string) error {
	if err := checkNPMRecentInterval(c, time.Now().UTC(), time.Now().UTC().Add(3*time.Minute)); err != nil {
		return err
	}
	return revalidateNPM(ctx, c, output)
}

func TestHarnessNPMRecentFreshness(t *testing.T) {
	var fixtures map[string]npmMetadata
	if err := readJSON("testdata/age_npm/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	metadata := fixtures["recent"]
	v, download, history, err := selectNPMRecent(metadata, "14.21.3", now)
	if err != nil || v != "1.0.0" || !download.UploadedAt.Equal(now.Add(-4*time.Hour)) || len(history) != 1 {
		t.Fatalf("wrong exact release/time/history: %s %+v %v %v", v, download, history, err)
	}
	if _, _, _, err := selectNPMRecent(metadata, "10.0.0", now); err == nil {
		t.Fatal("incompatible Node engine accepted")
	}
	for _, offset := range []time.Duration{-25 * time.Hour, -22 * time.Hour, -30 * time.Minute, time.Hour} {
		metadata.Time["1.0.0"] = now.Add(offset).Format(time.RFC3339)
		if _, _, _, err := selectNPMRecent(metadata, "14.21.3", now); err == nil {
			t.Errorf("accepted age offset%s", offset)
		}
	}
	if _, _, _, err := selectNPMRecent(fixtures["empty"], "14.21.3", now); err == nil {
		t.Fatal("empty search passed")
	}
	c := candidate{Ecosystem: "npm", Project: "fixture-leaf", Version: v, Artifacts: []artifact{download}, Metadata: []metadataEvidence{{}}, ObservedAt: now, LatestValidStart: download.UploadedAt.Add(npmAgeWindow - npmAgeMargin), AgeThresholdHours: 24, ApplicableCells: []string{"npm7"}}
	if err := validateNPMRecentCell(c, cell{ID: "npm7"}, now); err != nil {
		t.Fatal(err)
	}
	if err := validateNPMRecentCell(c, cell{ID: "npm10"}, now); err == nil {
		t.Fatal("manifest from another cell accepted")
	}
	if err := validateNPMRecentCell(c, cell{ID: "npm7"}, c.LatestValidStart); err == nil {
		t.Fatal("stale queue selection accepted")
	}
	if err := checkNPMRecentInterval(c, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := checkNPMRecentInterval(c, now, download.UploadedAt.Add(npmAgeWindow)); err == nil {
		t.Fatal("age expiry during execution passed")
	}
}
