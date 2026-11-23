// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// classicProxyCommand points Yarn Classic at the proxy. Only command options
// beat .yarnrc rc-args, so the proxy options go before the command name, where
// they cannot reach the arguments of `yarn run`; the user's own proxy options
// are removed because Yarn applies the last occurrence.
func classicProxyCommand(executable string, command []string, config proxy.ClientConfig, pem []byte) (proxy.CommandSpec, error) {
	dir, err := os.Getwd()
	if err != nil {
		return proxy.CommandSpec{}, errors.New("could not resolve yarn directory")
	}
	// `yarn workspace <name> <command>` only starts another Yarn in the
	// workspace, without these options. Running that command as if from the
	// workspace is equivalent and puts the options on the process that downloads.
	process, moved, err := classicTarget(dir, command, nodeproxy.LookupEnvironment(os.Environ()))
	if err != nil {
		return proxy.CommandSpec{}, err
	}
	if moved {
		command = process.relocated()
	}
	// Only the arguments Yarn parses itself carry its options; the rest belong
	// to the script or package a command runs.
	cmd, _, _ := parseYarnCommand(classic, command)
	args := []string{"--https-proxy=" + config.URL, "--proxy=" + config.URL}
	for index := 0; index < len(command); index++ {
		argument := command[index]
		if index >= cmd.end {
			args = append(args, command[index:]...)
			break
		}
		name, _, assigned := strings.Cut(argument, "=")
		if index == cmd.index || name != "--proxy" && name != "--https-proxy" {
			args = append(args, argument)
			continue
		}
		if !assigned && index+1 < cmd.end {
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
	return proxy.CommandSpec{Executable: executable, Args: args, EnvOverrides: nodeproxy.OverrideVariants(os.Environ(), canonical)}, nil
}

// relocated returns the command of a process that runs in a workspace as one
// run from the original directory. Its --cwd values are resolved against the
// workspace, and a leading --cwd makes Yarn read rc-args from where the
// process would: its first exact --cwd, else the workspace. Command-line
// options beat rc-args, so a process without a --cwd of its own restates the
// rc-arg --cwd it would use.
func (process classicProcess) relocated() []string {
	command := slices.Clone(process.command)
	start, exact, cwd := process.dir, false, false
	for index := 0; index < process.cmd.end; index++ {
		switch argument := command[index]; {
		case index == process.cmd.index:
		case argument == "--cwd" && index+1 < process.cmd.end:
			index++
			command[index] = resolvePath(process.dir, command[index])
			if !exact {
				start, exact = command[index], true
			}
			cwd = true
		case strings.HasPrefix(argument, "--cwd="):
			command[index] = "--cwd=" + resolvePath(process.dir, strings.TrimPrefix(argument, "--cwd="))
			cwd = true
		}
	}
	prefix := []string{"--cwd", start}
	if values := optionValues(process.rcArgs, "--cwd"); !cwd && len(values) > 0 {
		prefix = append(prefix, "--cwd="+filepath.Clean(values[len(values)-1]))
	}
	return append(prefix, command...)
}
