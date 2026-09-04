// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package age defines a package verifier that warns on packages published too
// recently, based on a user-configurable minimum age.
package age

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

const (
	// The environment variable under which the verifier looks for a
	// user-provided minimum package age, in hours.
	minimumAgeVar = "SCFW_PACKAGE_MINIMUM_AGE"

	// The default minimum age, expressed in hours.
	minimumAgeDefault = 24
)

// Verifier warns on packages that were published too recently.
type Verifier struct {
	minimumAge time.Duration
}

// New returns a PackageAgeVerifier with the minimum age resolved from the
// SCFW_PACKAGE_MINIMUM_AGE environment variable, falling back to the default
// of 24 hours when unset or invalid. A minimum age of 0 disables the verifier.
func New() Verifier {
	minimumAge := time.Duration(minimumAgeDefault) * time.Hour
	if value := os.Getenv(minimumAgeVar); value != "" {
		if hours, err := strconv.Atoi(value); err != nil || hours < 0 {
			slog.Warn("Invalid minimum package age; using default", "value", value, "default_hours", minimumAgeDefault)
		} else {
			minimumAge = time.Duration(hours) * time.Hour
		}
	}
	return Verifier{minimumAge: minimumAge}
}

// Name returns the verifier's name.
func (Verifier) Name() string {
	return "PackageAgeVerifier"
}

// Verify warns on the given package if it was published less than the
// configured minimum age ago. Packages with an unknown publish date, or from
// outside their ecosystem's registry (whose publish date cannot be resolved),
// are skipped rather than failed.
func (v Verifier) Verify(_ context.Context, pkg pm.Package) ([]evaluation.Finding, error) {
	if pkg.Ecosystem != ecosystem.NPM && pkg.Ecosystem != ecosystem.PYPI {
		return nil, fmt.Errorf("package ecosystem %s is not supported", pkg.Ecosystem)
	}
	if v.minimumAge == 0 {
		return nil, nil
	}
	if pkg.Source != "" && !ecosystem.HasRegistrySource(pkg.Ecosystem, pkg.Source) {
		return nil, nil
	}
	if pkg.PublishDate.IsZero() {
		slog.Debug("Could not determine package publish date", "verifier", v.Name(), "package", pkg.Name)
		return nil, nil
	}

	if time.Since(pkg.PublishDate) < v.minimumAge {
		minimumAgeHours := int(v.minimumAge.Hours())
		return []evaluation.Finding{{
			Verifier: v.Name(),
			Severity: evaluation.SeverityWarning,
			Text: fmt.Sprintf(
				"Package %s %s@%s was published less than %d hours ago: treat new releases with caution",
				pkg.Ecosystem, pkg.Name, pkg.Version, minimumAgeHours,
			),
		}}, nil
	}
	return nil, nil
}
