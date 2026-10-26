// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"context"
	"errors"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type PackageManager interface {
	Executable() string
	ProjectDirectory(command []string) (string, error)
	RunCommand(ctx context.Context, command []string) error
	ResolveInstallTargets(ctx context.Context, command []string) (*Set[Package], error)
}

// ProxyRunner is implemented by package managers that can run through the
// Supply Chain Firewall proxy, which evaluates packages as they are downloaded
// rather than resolving install targets ahead of time.
type ProxyRunner interface {
	// RunCommandThroughProxy runs command configured to route its traffic
	// through the given proxy, without changing any persistent package manager
	// configuration.
	RunCommandThroughProxy(ctx context.Context, command []string, config proxy.ClientConfig) error
}

// ErrUnsupportedVersion indicates that a package manager's version is too
// old to support safely, or that its version could not be determined.
var ErrUnsupportedVersion = errors.New("unsupported package manager version")
