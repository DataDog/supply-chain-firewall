// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
)

// Ecosystem aliases the shared identifier for callers of registry operations.
type Ecosystem = common.Ecosystem

const (
	NPM  = common.NPM
	PYPI = common.PYPI
)

// NormalizePackageName returns the ecosystem's canonical package name. Names
// without a registered normalization rule are preserved.
func NormalizePackageName(packageEcosystem Ecosystem, name string) string {
	if packageEcosystem == PYPI {
		return pypi.NormalizeName(name)
	}
	return name
}

// HasRegistrySource reports whether source is a known registry URL in the given
// ecosystem, dispatching to the ecosystem-specific implementation. An empty source
// is treated as unknown, and callers decide how to handle it.
func HasRegistrySource(ecosystem Ecosystem, source string) bool {
	switch ecosystem {
	case NPM:
		return npm.HasRegistrySource(source)
	case PYPI:
		return pypi.HasRegistrySource(source)
	default:
		return false
	}
}

// ResolvePublishDate resolves the publish date of the given package name/version/source
// in the given ecosystem, dispatching to the ecosystem-specific implementation.
func ResolvePublishDate(ctx context.Context, ecosystem Ecosystem, name, version, source string) (time.Time, error) {
	switch ecosystem {
	case NPM:
		return npm.ResolvePublishDate(ctx, name, version, source)
	case PYPI:
		return pypi.ResolvePublishDate(ctx, name, version, source)
	default:
		return time.Time{}, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}
