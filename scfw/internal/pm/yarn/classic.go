// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"maps"
	"os"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// classicProxyCommand points Yarn Classic at the proxy. Only command options
// beat .yarnrc rc-args, so the proxy options go before the command name, where
// they cannot reach the arguments of `yarn run`; the user's own proxy options
// are removed because Yarn applies the last occurrence.
func classicProxyCommand(executable string, command []string, config proxy.ClientConfig, pem []byte) (proxy.CommandSpec, error) {
	args := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL}
	for index := 0; index < len(command); index++ {
		argument := command[index]
		if argument == "--" {
			args = append(args, command[index:]...)
			break
		}
		name, _, assigned := strings.Cut(argument, "=")
		if name != "--proxy" && name != "--https-proxy" {
			args = append(args, argument)
			continue
		}
		if !assigned {
			index++
		}
	}
	extraCAs, err := nodeproxy.NodeExtraCACerts(config.CACertificatePath, pem)
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	// Lifecycle scripts see Yarn's resolved configuration, not its command
	// options, so the Yarn variables also route nested yarn and npm calls.
	canonical := config.EnvironmentOverrides()
	maps.Copy(canonical, map[string]string{
		"YARN_PROXY": config.URL, "YARN_HTTPS_PROXY": config.URL, "YARN_CAFILE": config.CACertificatePath,
		"npm_config_proxy": config.URL, "npm_config_https_proxy": config.URL,
		"npm_config_cafile": config.CACertificatePath, "npm_config_noproxy": "scfw.invalid",
		"GIT_SSL_CAINFO": config.CACertificatePath, "NODE_EXTRA_CA_CERTS": extraCAs,
	})
	return proxy.CommandSpec{Executable: executable, Args: args, EnvOverrides: overrideVariants(os.Environ(), canonical)}, nil
}

// overrideVariants gives every variant of a canonical key already present in
// environ the canonical value. Yarn and npm read their variables
// case-insensitively and accept dashes for underscores, while the core
// replaces exact keys only.
func overrideVariants(environ []string, canonical map[string]string) map[string]string {
	normalized := make(map[string]string, len(canonical))
	for key, value := range canonical {
		normalized[strings.ToLower(key)] = value
	}
	overrides := maps.Clone(canonical)
	for _, item := range environ {
		key, _, _ := strings.Cut(item, "=")
		if value, found := normalized[strings.ReplaceAll(strings.ToLower(key), "-", "_")]; found {
			overrides[key] = value
		}
	}
	return overrides
}
