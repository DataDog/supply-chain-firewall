// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"maps"
	"os"
	"slices"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// berryProxyCommand points Yarn 4 at the proxy through its own variables,
// which beat every rc file. Yarn 4 ignores the standard proxy variables, which
// still route Git and lifecycle scripts. The arguments are left unchanged:
// Yarn 4 rejects Classic's proxy options.
func berryProxyCommand(executable string, command []string, config proxy.ClientConfig, pem []byte) (proxy.CommandSpec, error) {
	extraCAs, err := nodeproxy.NodeExtraCACerts(config.CACertificatePath, pem)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	// Before Yarn 4.9.2 proxied requests trust only NODE_EXTRA_CA_CERTS; later
	// versions replace the roots with YARN_HTTPS_CA_FILE_PATH.
	canonical := config.EnvironmentOverrides()
	maps.Copy(canonical, map[string]string{
		"YARN_HTTPS_PROXY": config.URL, "YARN_HTTP_PROXY": config.URL,
		"YARN_HTTPS_CA_FILE_PATH": config.CACertificatePath,
		"GIT_SSL_CAINFO":          config.CACertificatePath, "NODE_EXTRA_CA_CERTS": extraCAs,
	})
	return proxy.CommandSpec{Executable: executable, Args: slices.Clone(command), EnvOverrides: overrideVariants(os.Environ(), canonical)}, nil
}
