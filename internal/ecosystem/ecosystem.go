// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ecosystem

import (
	"context"
	"fmt"
	"time"
)

type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PYPI Ecosystem = "PyPI"
)

// ResolvePublishDate resolves the publish date of the given package name/version/source
// in the given ecosystem, dispatching to the ecosystem-specific implementation.
func ResolvePublishDate(ctx context.Context, ecosystem Ecosystem, name, version, source string) (time.Time, error) {
	switch ecosystem {
	case NPM:
		return resolveNpmPublishDate(ctx, name, version, source)
	case PYPI:
		return resolvePyPIPublishDate(ctx, name, version, source)
	default:
		return time.Time{}, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}
