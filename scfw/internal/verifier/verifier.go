// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package verifier defines the local package verification framework:
// the Verifier interface that concrete verifiers (OSV.dev, the Datadog
// malicious-software-packages-dataset, package age, findings lists) implement.
package verifier

import (
	"context"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// Verifier verifies packages against a single source of truth about vulnerable
// or malicious packages. Verify returns the findings for pkg; a returned error
// means the package could not be verified and is recorded as a verification
// failure for the package.
type Verifier interface {
	// Name returns a constant, short, descriptive name identifying the verifier.
	Name() string
	// Verify reports the findings for the given package.
	Verify(ctx context.Context, pkg pm.Package) ([]evaluation.Finding, error)
}
