//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type pypiFile struct {
	Filename       string    `json:"filename"`
	URL            string    `json:"url"`
	UploadTime     time.Time `json:"upload_time_iso_8601"`
	Yanked         bool      `json:"yanked"`
	RequiresPython string    `json:"requires_python"`
	Digests        struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}
type pypiMetadata struct {
	Releases map[string][]pypiFile `json:"releases"`
	URLs     []pypiFile            `json:"urls"`
	Info     struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"info"`
}

func init() { discoverers["pypi-old"] = discoverPyPIOld; revalidators["pypi-old"] = revalidatePyPI }
func fetchJSON(ctx context.Context, url, path string, target any) (metadataEvidence, error) {
	evidence := metadataEvidence{URL: url, FetchedAt: time.Now().UTC()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return evidence, err
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return evidence, classified("INFRASTRUCTURE_FAILURE", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20+1))
	if err != nil {
		return evidence, classified("INFRASTRUCTURE_FAILURE", err)
	}
	if len(body) > 16<<20 {
		return evidence, fmt.Errorf("registry metadata exceeds16MiB")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return evidence, err
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		return evidence, err
	}
	evidence.Body, err = digestFile(path)
	if err != nil {
		return evidence, err
	}
	if response.StatusCode != http.StatusOK {
		return evidence, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("registry returned HTTP%d for %s; body retained at %s", response.StatusCode, url, path))
	}
	if err := json.Unmarshal(body, target); err != nil {
		return evidence, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("invalid registry metadata: %w", err))
	}
	return evidence, nil
}
func discoverPyPIOld(ctx context.Context, c cell, output string) (candidate, error) {
	var pool []struct {
		Name   string `json:"name"`
		Module string `json:"module"`
	}
	if err := readJSON("testdata/pypi_candidates.json", &pool); err != nil {
		return candidate{}, err
	}
	now := time.Now().UTC()
	var rejected []string
	for _, item := range pool {
		var metadata pypiMetadata
		evidence, err := fetchJSON(ctx, "https://pypi.org/pypi/"+item.Name+"/json", filepath.Join(output, item.Name+".json"), &metadata)
		if err != nil {
			return candidate{}, err
		}
		type choice struct {
			version string
			file    pypiFile
		}
		var choices []choice
		for version, files := range metadata.Releases {
			if !regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(version) {
				continue
			}
			for _, file := range files {
				if file.Yanked || file.UploadTime.After(now.Add(-48*time.Hour)) || !strings.HasSuffix(file.Filename, "py3-none-any.whl") || !compatiblePythonFloor(file.RequiresPython, c.RuntimeVersion) {
					continue
				}
				choices = append(choices, choice{version, file})
			}
		}
		if len(choices) == 0 {
			rejected = append(rejected, item.Name+": no non-yanked universal wheel older than48h compatible with runtime")
			continue
		}
		slices.SortFunc(choices, func(a, b choice) int { return b.file.UploadTime.Compare(a.file.UploadTime) })
		chosen := choices[0]
		return candidate{Ecosystem: "pypi", Project: metadata.Info.Name, Version: chosen.version, Module: item.Module, Property: "old-wheel", Metadata: []metadataEvidence{evidence}, Artifacts: []artifact{{Name: chosen.file.Filename, URL: chosen.file.URL, SHA256: chosen.file.Digests.SHA256, UploadedAt: chosen.file.UploadTime, RequiresPython: chosen.file.RequiresPython}}, ObservedAt: now, LatestValidStart: now.Add(24 * time.Hour), Constraints: []string{"pure Python3 universal wheel", c.RuntimeVersion, "no dependency installation"}, Evidence: append(rejected, "selected newest eligible upload; no reroll after SCFW execution")}, nil
	}
	return candidate{}, classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("no eligible public PyPI candidate: %v", rejected))
}

// The maintained pool uses simple Python3 lower bounds. Unknown expressions are
// rejected, rather than pretending to implement all Python version specifiers.
func compatiblePythonFloor(spec, version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || parts[0] != "3" {
		return false
	}
	if spec == "" {
		return true
	}
	match := regexp.MustCompile(`^>=3\.(\d+)(\.0)?$`).FindStringSubmatch(spec)
	if match == nil {
		return false
	}
	minimum, err := strconv.Atoi(match[1])
	if err != nil {
		return false
	}
	actual, err := strconv.Atoi(parts[1])
	return err == nil && actual >= minimum
}
func revalidatePyPI(ctx context.Context, c candidate, output string) error {
	var metadata pypiMetadata
	_, err := fetchJSON(ctx, "https://pypi.org/pypi/"+c.Project+"/"+c.Version+"/json", filepath.Join(output, "pypi.json"), &metadata)
	if err != nil {
		return err
	}
	for _, expected := range c.Artifacts {
		found := false
		for _, file := range metadata.URLs {
			if file.Filename == expected.Name && file.URL == expected.URL && file.Digests.SHA256 == expected.SHA256 && file.UploadTime.Equal(expected.UploadedAt) && !file.Yanked {
				found = true
			}
		}
		if !found {
			return classified("PRECONDITION_UNAVAILABLE", fmt.Errorf("discovered artifact %s was removed, yanked or changed", expected.Name))
		}
	}
	return nil
}
