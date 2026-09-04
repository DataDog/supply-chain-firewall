// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package list

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func writeList(t *testing.T, name, contents string) {
	t.Helper()
	listsHome := filepath.Join(os.Getenv("SCFW_HOME"), verifierHome)
	if err := os.MkdirAll(listsHome, 0o755); err != nil {
		t.Fatalf("failed to create findings list directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(listsHome, name), []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write findings list: %v", err)
	}
}

func TestVerifyReportsListedFindings(t *testing.T) {
	t.Setenv("SCFW_HOME", t.TempDir())
	writeList(t, "findings.yml", `
findings:
  - severity: CRITICAL
    finding: known-malicious-package
    packages:
      - ecosystem: NPM
        name: evil-1
        versions: ["*"]
  - severity: warning
    finding: pinned to a compromised version
    packages:
      - ecosystem: PyPI
        name: evil-2
        versions: ["2.0.0"]
`)

	v := New()

	findings, err := v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.NPM, Name: "evil-1", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != evaluation.SeverityCritical || findings[0].Text != "known-malicious-package" {
		t.Fatalf("findings = %+v, want the CRITICAL finding", findings)
	}

	findings, err = v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.PYPI, Name: "evil-2", Version: "2.0.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != evaluation.SeverityWarning {
		t.Fatalf("findings = %+v, want the version-pinned WARNING finding", findings)
	}

	findings, err = v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.PYPI, Name: "evil-2", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a non-listed version", findings)
	}

	findings, err = v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.PYPI, Name: "six", Version: "1.17.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for an unlisted package", findings)
	}
}

func TestVerifyRejectsNonRegistrySources(t *testing.T) {
	t.Setenv("SCFW_HOME", t.TempDir())
	writeList(t, "findings.yml", `
findings:
  - severity: CRITICAL
    finding: known-malicious-package
    packages:
      - ecosystem: npm
        name: evil-1
`)

	v := New()

	findings, err := v.Verify(context.Background(), pm.Package{
		Ecosystem: ecosystem.NPM,
		Name:      "evil-1",
		Version:   "1.0.0",
		Source:    "file:///tmp/evil-1",
	})
	if err == nil {
		t.Fatal("Verify() returned nil error, want non-registry source error")
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a non-registry source", findings)
	}
}

func TestNewSkipsInvalidLists(t *testing.T) {
	t.Setenv("SCFW_HOME", t.TempDir())
	writeList(t, "invalid-severity.yml", `
findings:
  - severity: SEVERE
    finding: invalid severity
    packages:
      - ecosystem: npm
        name: evil-1
`)
	writeList(t, "not-yaml.yml", "\t: not yaml")

	v := New()

	findings, err := v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.NPM, Name: "evil-1", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none when all lists are invalid", findings)
	}
}

func TestNewWithoutFindingsListsHasNoFindings(t *testing.T) {
	t.Setenv("SCFW_HOME", t.TempDir())
	v := New()
	findings, err := v.Verify(context.Background(), pm.Package{Ecosystem: ecosystem.NPM, Name: "evil-1", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none without any findings list", findings)
	}
}
