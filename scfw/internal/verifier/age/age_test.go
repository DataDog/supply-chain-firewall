// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package age

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestVerifyWarnsOnRecentPackages(t *testing.T) {
	v := New()

	recent := pm.Package{
		Ecosystem:   ecosystem.NPM,
		Name:        "left-pad",
		Version:     "1.3.0",
		PublishDate: time.Now().Add(-1 * time.Hour),
	}
	findings, err := v.Verify(context.Background(), recent)
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != evaluation.SeverityWarning {
		t.Fatalf("findings = %+v, want a single WARNING finding", findings)
	}
	if !strings.Contains(findings[0].Text, "published less than") {
		t.Errorf("finding text does not mention the publish age: %q", findings[0].Text)
	}

	old := pm.Package{
		Ecosystem:   ecosystem.PYPI,
		Name:        "six",
		Version:     "1.17.0",
		PublishDate: time.Now().Add(-48 * time.Hour),
	}
	findings, err = v.Verify(context.Background(), old)
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for an old package", findings)
	}
}

func TestVerifySkipsUnknownAndNonRegistryPackages(t *testing.T) {
	v := New()

	unknownDate := pm.Package{Ecosystem: ecosystem.NPM, Name: "left-pad", Version: "1.3.0"}
	findings, err := v.Verify(context.Background(), unknownDate)
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a package with unknown publish date", findings)
	}

	git := pm.Package{
		Ecosystem:   ecosystem.NPM,
		Name:        "left-pad",
		Version:     "1.3.0",
		Source:      "https://example.com/left-pad.git",
		PublishDate: time.Now(),
	}
	findings, err = v.Verify(context.Background(), git)
	if err != nil {
		t.Fatalf("Verify() returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a non-registry package", findings)
	}
}

func TestMinimumAgeFromEnvironment(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		t.Setenv(minimumAgeVar, "0")
		v := New()
		findings, err := v.Verify(context.Background(), pm.Package{
			Ecosystem:   ecosystem.NPM,
			Name:        "left-pad",
			Version:     "1.3.0",
			PublishDate: time.Now(),
		})
		if err != nil {
			t.Fatalf("Verify() returned unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("findings = %+v, want none with the verifier disabled", findings)
		}
	})

	t.Run("custom", func(t *testing.T) {
		t.Setenv(minimumAgeVar, "100")
		v := New()
		findings, err := v.Verify(context.Background(), pm.Package{
			Ecosystem:   ecosystem.NPM,
			Name:        "left-pad",
			Version:     "1.3.0",
			PublishDate: time.Now().Add(-50 * time.Hour),
		})
		if err != nil {
			t.Fatalf("Verify() returned unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("findings = %+v, want one for a package under the custom minimum age", findings)
		}
	})

	t.Run("invalid falls back to default", func(t *testing.T) {
		t.Setenv(minimumAgeVar, "not-a-number")
		v := New()
		if v.minimumAge != minimumAgeDefault*time.Hour {
			t.Errorf("minimumAge = %v, want the %dh default", v.minimumAge, minimumAgeDefault)
		}
	})
}

func TestVerifyRejectsUnsupportedEcosystem(t *testing.T) {
	v := New()
	if _, err := v.Verify(context.Background(), pm.Package{Name: "unknown-ecosystem", Version: "1.0.0"}); err == nil {
		t.Error("Verify() succeeded for an unsupported ecosystem, want error")
	}
}
