// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// newTestVerifier returns an OsvVerifier querying url, with the ignore list
// read from ignoreFile (or no ignore list when empty).
func newTestVerifier(t *testing.T, url, ignoreFile string) Verifier {
	t.Helper()
	t.Setenv("SCFW_HOME", t.TempDir())
	if ignoreFile != "" {
		t.Setenv(ignoreListVar, ignoreFile)
	} else {
		t.Setenv(ignoreListVar, filepath.Join(t.TempDir(), "nonexistent.txt"))
	}
	return newVerifier(url)
}

func TestVerifyReportsAdvisoriesWithSeverity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []any{
				map[string]any{"id": "GHSA-1234-5678-9abc"},
				map[string]any{"id": "MAL-2024-0001"},
			},
		})
	}))
	defer server.Close()

	v := newTestVerifier(t, server.URL, "")
	pkg := pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"}

	findings, err := v.Verify(context.Background(), pkg)
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}

	severities := map[evaluation.Severity]bool{}
	for _, finding := range findings {
		severities[finding.Severity] = true
	}
	if !severities[evaluation.SeverityCritical] {
		t.Errorf("missing CRITICAL finding for the MAL advisory: %+v", findings)
	}
	if !severities[evaluation.SeverityWarning] {
		t.Errorf("missing WARNING finding for the GHSA advisory: %+v", findings)
	}

	var critical, warning evaluation.Finding
	for _, finding := range findings {
		if finding.Severity == evaluation.SeverityCritical {
			critical = finding
		} else {
			warning = finding
		}
	}
	if !strings.Contains(critical.Text, "MAL-2024-0001") {
		t.Errorf("CRITICAL finding does not reference the MAL advisory: %q", critical.Text)
	}
	if !strings.Contains(warning.Text, "GHSA-1234-5678-9abc") {
		t.Errorf("WARNING finding does not reference the GHSA advisory: %q", warning.Text)
	}
}

func TestVerifyFollowsPagination(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		response := map[string]any{
			"vulns": []any{map[string]any{"id": "GHSA-aaaa-bbbb-cccc"}},
		}
		if requests == 1 {
			response["next_page_token"] = "page-2"
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	v := newTestVerifier(t, server.URL, "")
	findings, err := v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.17.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2 (one per page)", len(findings))
	}
	if requests != 2 {
		t.Errorf("API requests = %d, want 2", requests)
	}
}

func TestVerifyFailsOpenToWarningOnAPIFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := newTestVerifier(t, server.URL, "")
	findings, err := v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != evaluation.SeverityWarning {
		t.Fatalf("findings = %+v, want a single WARNING finding", findings)
	}
	if !strings.Contains(findings[0].Text, "check the OSV.dev website") {
		t.Errorf("failure finding does not direct the user to the OSV.dev website: %q", findings[0].Text)
	}
}

func TestVerifyRejectsUnsupportedPackages(t *testing.T) {
	v := newTestVerifier(t, "http://unused.invalid", "")

	if _, err := v.Verify(context.Background(), pm.Package{Name: "unknown-ecosystem", Version: "1.0.0"}); err == nil {
		t.Error("Verify() succeeded for an unsupported ecosystem, want error")
	}
	if _, err := v.Verify(context.Background(), pm.Package{
		Ecosystem: ecosystem.NPM,
		Name:      "left-pad",
		Version:   "1.3.0",
		Source:    "https://example.com/left-pad.git",
	}); err == nil {
		t.Error("Verify() succeeded for a non-registry source, want error")
	}
}

func TestIgnoreListFiltersAdvisoriesButNeverMAL(t *testing.T) {
	ignoreFile := filepath.Join(t.TempDir(), "ignore.txt")
	if err := os.WriteFile(ignoreFile, []byte("GHSA-1234-5678-9abc\n\n"), 0o644); err != nil {
		t.Fatalf("failed to write ignore list: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []any{
				map[string]any{"id": "GHSA-1234-5678-9abc"},
				map[string]any{"id": "GHSA-9999-8888-7777"},
				map[string]any{"id": "MAL-2024-0001"},
			},
		})
	}))
	defer server.Close()

	v := newTestVerifier(t, server.URL, ignoreFile)
	findings, err := v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}

	var ids []string
	for _, finding := range findings {
		for _, part := range strings.Split(finding.Text, "/") {
			if strings.HasPrefix(part, "GHSA-") || strings.HasPrefix(part, "MAL-") {
				ids = append(ids, part)
			}
		}
	}
	if strings.Join(ids, ",") != "GHSA-9999-8888-7777,MAL-2024-0001" {
		t.Errorf("reported advisory IDs = %v, want the unignored GHSA and the MAL advisory", ids)
	}
}

func TestReadIgnoredIDsWarnsButProceedsOnMALPattern(t *testing.T) {
	ignoreFile := filepath.Join(t.TempDir(), "ignore.txt")
	if err := os.WriteFile(ignoreFile, []byte("MAL-.*\n"), 0o644); err != nil {
		t.Fatalf("failed to write ignore list: %v", err)
	}

	t.Setenv("SCFW_HOME", t.TempDir())
	t.Setenv(ignoreListVar, ignoreFile)

	if ignored := readIgnoredIDs(); len(ignored) != 0 {
		t.Errorf("readIgnoredIDs() = %v, want no ignore patterns (MAL never ignored)", ignored)
	}
}
