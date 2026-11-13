// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import "context"

// ArtifactStatus distinguishes inconsistent artifacts from incomplete verification.
type ArtifactStatus string

const (
	ArtifactMatched       ArtifactStatus = "matched"
	ArtifactMismatched    ArtifactStatus = "mismatched"
	ArtifactUnverifiable  ArtifactStatus = "unverifiable"
	ArtifactNotApplicable ArtifactStatus = "not_applicable"
)

// ArtifactResult contains safe evidence from an invocation's mandatory artifact gate.
// Detail must not contain manifest values, credentials, or raw transport errors.
type ArtifactResult struct {
	Package            Package
	Status             ArtifactStatus
	Reason             string
	Detail             string
	IntegrityAvailable bool
}

// ArtifactResolver performs preflight resolution and verifies its selected bytes.
type ArtifactResolver interface {
	ResolveVerifiedInstallTargets(context.Context, []string) (*Set[Package], []ArtifactResult, error)
}
