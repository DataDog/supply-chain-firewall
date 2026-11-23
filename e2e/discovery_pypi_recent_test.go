//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const pypiRecentWindow = 24 * time.Hour
const pypiRecentMargin = 2 * time.Hour

type pypiRecentMetadata struct {
	URLs []pypiFile `json:"urls"`
	Info struct {
		Name         string   `json:"name"`
		Version      string   `json:"version"`
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
}

func init() {
	discoverers["pypi-recent"] = discoverPyPIRecent
	revalidators["pypi-recent"] = revalidatePyPIRecent
}

func pypiReleaseFeed(ctx context.Context, output string) ([]string, metadataEvidence, error) {
	const endpoint = "https://pypi.org/rss/updates.xml"
	evidence := metadataEvidence{URL: endpoint, FetchedAt: time.Now().UTC()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, evidence, err
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return nil, evidence, classified("INFRASTRUCTURE_FAILURE", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		return nil, evidence, classified("INFRASTRUCTURE_FAILURE", err)
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return nil, evidence, err
	}
	path := filepath.Join(output, "releases.xml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		return nil, evidence, err
	}
	evidence.Body, err = digestFile(path)
	if err != nil {
		return nil, evidence, err
	}
	if response.StatusCode != http.StatusOK || len(body) > 1<<20 {
		return nil, evidence, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("PyPI feed status %d or oversized body", response.StatusCode))
	}
	var feed struct {
		Items []struct {
			Link string `xml:"link"`
		} `xml:"channel>item"`
	}
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, evidence, classified("INFRASTRUCTURE_FAILURE", err)
	}
	var names []string
	for _, item := range feed.Items {
		u, err := url.Parse(item.Link)
		if err != nil || u.Scheme != "https" || u.Host != "pypi.org" {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) == 3 && parts[0] == "project" && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(parts[1]) && !slices.Contains(names, parts[1]) {
			names = append(names, parts[1])
		}
		if len(names) == 40 {
			break
		}
	}
	return names, evidence, nil
}

func discoverPyPIRecent(ctx context.Context, current cell, output string) (chosen candidate, err error) {
	var history []string
	var snapshots []metadataEvidence
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
	names, feed, err := pypiReleaseFeed(ctx, output)
	snapshots = append(snapshots, feed)
	if err != nil {
		return chosen, err
	}
	var pool []string
	if err := readJSON("testdata/age_pypi/candidates.json", &pool); err != nil {
		return chosen, err
	}
	if len(pool) == 0 || len(pool) > 8 {
		return chosen, fmt.Errorf("expected one to eight maintained PyPI candidates")
	}
	// Prefer maintained projects; the feed supplies a bounded fallback search.
	for _, name := range names {
		if !slices.Contains(pool, name) {
			pool = append(pool, name)
		}
	}
	var m matrix
	if err := readJSON(os.Getenv("SCFW_E2E_MATRIX"), &m); err != nil {
		return chosen, err
	}
	for index, name := range pool {
		var metadata pypiRecentMetadata
		snapshot, fetchErr := fetchJSON(ctx, "https://pypi.org/pypi/"+name+"/json", filepath.Join(output, fmt.Sprintf("%02d.json", index)), &metadata)
		snapshots = append(snapshots, snapshot)
		if fetchErr != nil {
			return chosen, fetchErr
		}
		now := time.Now().UTC()
		artifacts, selectErr := selectPyPIRecent(metadata, current.RuntimeVersion, now)
		if selectErr != nil {
			history = append(history, name+": "+selectErr.Error())
			continue
		}
		var applicable []string
		for _, other := range m.Cells {
			if !slices.Contains([]string{"pip", "poetry", "uv"}, other.Manager) || !slices.Contains(other.Suites, "pypi-recent") {
				continue
			}
			if _, err := selectPyPIRecent(metadata, other.RuntimeVersion, now); err == nil {
				applicable = append(applicable, other.ID)
			}
		}
		latest := artifacts[0].UploadedAt.Add(pypiRecentWindow - pypiRecentMargin)
		for _, a := range artifacts {
			if limit := a.UploadedAt.Add(pypiRecentWindow - pypiRecentMargin); limit.Before(latest) {
				latest = limit
			}
		}
		chosen = candidate{Ecosystem: "pypi", Project: metadata.Info.Name, Version: metadata.Info.Version, Property: "recent-wheel", Metadata: snapshots, Artifacts: artifacts, ObservedAt: now, LatestValidStart: latest, AgeThresholdHours: 24, ApplicableCells: applicable, Constraints: []string{"one universal wheel; no runtime dependencies; all release files younger than22h", current.RuntimeVersion}, Evidence: append(history, "exact release selected once; all upload times cover artifact and latest-file resolution policies; no reroll after SCFW")}
		return chosen, nil
	}
	return chosen, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no eligible recent PyPI release; retained bounded search at %s", output))
}

// Accept only absent dependencies or simple opt-in extras; no extras are installed.
func pypiRecentLeaf(dependencies []string) bool {
	for _, dependency := range dependencies {
		marker := strings.SplitN(dependency, ";", 2)
		if len(marker) != 2 || !regexp.MustCompile(`^\s*extra\s*==\s*["'][A-Za-z0-9._-]+["']\s*$`).MatchString(marker[1]) {
			return false
		}
	}
	return true
}

func selectPyPIRecent(metadata pypiRecentMetadata, runtime string, now time.Time) ([]artifact, error) {
	if metadata.Info.Name == "" || !regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(metadata.Info.Version) || !pypiRecentLeaf(metadata.Info.RequiresDist) || len(metadata.URLs) == 0 {
		return nil, fmt.Errorf("not a stable dependency-free release")
	}
	var wheel []artifact
	var other []artifact
	for _, file := range metadata.URLs {
		if file.Yanked || file.UploadTime.IsZero() || file.UploadTime.After(now) || !now.Before(file.UploadTime.Add(pypiRecentWindow-pypiRecentMargin)) || len(file.Digests.SHA256) != 64 {
			return nil, fmt.Errorf("yanked, incomplete, future or stale release artifact")
		}
		u, err := url.Parse(file.URL)
		if err != nil || u.Scheme != "https" || u.Host != "files.pythonhosted.org" {
			return nil, fmt.Errorf("artifact is not on public PyPI storage")
		}
		a := artifact{Name: file.Filename, URL: file.URL, SHA256: file.Digests.SHA256, UploadedAt: file.UploadTime, RequiresPython: file.RequiresPython}
		if strings.HasSuffix(file.Filename, ".whl") {
			if !strings.HasSuffix(file.Filename, "py3-none-any.whl") || !compatiblePythonFloor(file.RequiresPython, runtime) {
				return nil, fmt.Errorf("wheel is not universal or Python compatible")
			}
			wheel = append(wheel, a)
		} else {
			other = append(other, a)
		}
	}
	if len(wheel) != 1 {
		return nil, fmt.Errorf("expected exactly one eligible universal wheel")
	}
	return append(wheel, other...), nil
}

func checkPyPIRecentInterval(c candidate, start, end time.Time) error {
	if len(c.Artifacts) == 0 || end.Before(start) {
		return fmt.Errorf("invalid recent PyPI interval or artifacts")
	}
	for _, a := range c.Artifacts {
		if a.UploadedAt.After(start) || !end.Before(a.UploadedAt.Add(pypiRecentWindow)) {
			return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("PyPI file %s age does not hold throughout [%s,%s]", a.Name, start, end))
		}
	}
	return nil
}

func validatePyPIRecentCell(c candidate, current cell, now time.Time) error {
	if c.AgeThresholdHours != 24 || !slices.Contains(c.ApplicableCells, current.ID) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("recent PyPI threshold or compatible cell mismatch"))
	}
	return classified("PRECONDITION_UNAVAILABLE", validateCandidate(c, now))
}

func revalidatePyPIRecent(ctx context.Context, c candidate, output string) error {
	var metadata pypiRecentMetadata
	snapshot, err := fetchJSON(ctx, "https://pypi.org/pypi/"+c.Project+"/"+c.Version+"/json", filepath.Join(output, "pypi.json"), &metadata)
	if err != nil {
		return err
	}
	if metadata.Info.Name != c.Project || metadata.Info.Version != c.Version || !pypiRecentLeaf(metadata.Info.RequiresDist) || len(metadata.URLs) != len(c.Artifacts) {
		return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("release identity, dependency or file inventory changed"))
	}
	for _, expected := range c.Artifacts {
		if !slices.ContainsFunc(metadata.URLs, func(f pypiFile) bool {
			return !f.Yanked && f.Filename == expected.Name && f.URL == expected.URL && f.Digests.SHA256 == expected.SHA256 && f.RequiresPython == expected.RequiresPython && f.UploadTime.Equal(expected.UploadedAt)
		}) {
			return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("release file %s changed or disappeared", expected.Name))
		}
	}
	revision := c
	revision.Metadata = append(slices.Clone(c.Metadata), snapshot)
	revision.ObservedAt = snapshot.FetchedAt
	if err := writeJSON(filepath.Join(output, "revision.json"), revision); err != nil {
		return err
	}
	return checkPyPIRecentInterval(c, time.Now().UTC(), time.Now().UTC().Add(4*time.Minute))
}

func TestHarnessPyPIRecentEligibility(t *testing.T) {
	var fixtures map[string]pypiRecentMetadata
	if err := readJSON("testdata/age_pypi/responses.json", &fixtures); err != nil {
		t.Fatal(err)
	}
	if !pypiRecentLeaf([]string{`pytest>=8; extra == "test"`}) || pypiRecentLeaf([]string{`pytest; extra == "test" or python_version >= "3"`}) {
		t.Fatal("incorrect optional dependency eligibility")
	}
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	files, err := selectPyPIRecent(fixtures["recent"], "3.11.18", now)
	if err != nil || len(files) != 2 || files[0].Name != "fixture_leaf-1.0-py3-none-any.whl" {
		t.Fatalf("selection: %+v %v", files, err)
	}
	for _, name := range []string{"empty", "yanked", "future", "stale-sdist", "dependencies", "incompatible"} {
		if _, err := selectPyPIRecent(fixtures[name], "3.11.18", now); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	c := candidate{Ecosystem: "pypi", Project: "fixture-leaf", Version: "1.0", Metadata: []metadataEvidence{{}}, Artifacts: files, ObservedAt: now, LatestValidStart: files[1].UploadedAt.Add(pypiRecentWindow - pypiRecentMargin), AgeThresholdHours: 24, ApplicableCells: []string{"pip", "poetry", "uv"}}
	for _, id := range c.ApplicableCells {
		if err := validatePyPIRecentCell(c, cell{ID: id}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := validatePyPIRecentCell(c, cell{ID: "pip"}, c.LatestValidStart); err == nil {
		t.Fatal("accepted queue-time expiry")
	}
	if err := validatePyPIRecentCell(c, cell{ID: "other"}, now); err == nil {
		t.Fatal("accepted incompatible cell")
	}
	if err := checkPyPIRecentInterval(c, now, files[1].UploadedAt.Add(pypiRecentWindow)); err == nil {
		t.Fatal("accepted expiry of an alternate artifact during execution")
	}
}
