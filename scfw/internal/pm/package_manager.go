// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"context"
	"errors"
)

type PackageManager interface {
	Executable() string
	ProjectDirectory(command []string) (string, error)
	RunCommand(ctx context.Context, command []string) error
	ResolveInstallTargets(ctx context.Context, command []string) (*Set[Package], error)
}

// ErrUnsupportedVersion indicates that a package manager's version is too
// old to support safely, or that its version could not be determined.
var ErrUnsupportedVersion = errors.New("unsupported package manager version")
