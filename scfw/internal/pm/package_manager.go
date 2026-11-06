// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"context"
	"errors"

	"golang.org/x/net/http/httpproxy"

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
	// UpstreamProxy returns the proxy configuration the package manager would
	// use for command without SCFW, so that the SCFW proxy can chain to it.
	UpstreamProxy(command []string) (httpproxy.Config, error)
	// The core defines the command contract; adapters implement it without
	// making the core depend on this package.
	proxy.CommandConfigurer
}

// ProxyOptionsProvider extends upstream discovery with invocation-scoped TLS
// trust for package managers whose registry trust differs from the system roots.
type ProxyOptionsProvider interface {
	ProxyOptions(command []string) (proxy.Options, error)
}

// ErrUnsupportedVersion indicates that a package manager's version is too
// old to support safely, or that its version could not be determined.
var ErrUnsupportedVersion = errors.New("unsupported package manager version")
