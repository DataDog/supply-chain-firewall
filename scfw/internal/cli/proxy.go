// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	registryproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy -- npm <args...>",
	Short: "Run npm through an experimental local registry proxy.",
	Args:  validateProxyArgs,
	RunE:  runProxy,
}

func init() {
	proxyCmd.Flags().Int("http-status", 0, "Return this HTTP status for intercepted requests without contacting the registry")
}

func validateProxyArgs(cmd *cobra.Command, args []string) error {
	httpStatus, err := cmd.Flags().GetInt("http-status")
	if err != nil {
		return fmt.Errorf("scfw proxy: read --http-status: %w", err)
	}
	if cmd.Flags().Changed("http-status") && (httpStatus < 200 || httpStatus > 599) {
		return fmt.Errorf("scfw proxy: invalid --http-status %d: must be between 200 and 599", httpStatus)
	}
	dash := cmd.ArgsLenAtDash()
	if dash == -1 {
		return fmt.Errorf("scfw proxy: missing \"--\" separator before command (usage: %s)", cmd.UseLine())
	}
	if dash != 0 {
		return fmt.Errorf("scfw proxy: unexpected argument(s) before \"--\": %s", strings.Join(args[:dash], " "))
	}
	if len(args) == dash {
		return errors.New("scfw proxy: no command specified after \"--\"")
	}
	if filepath.Base(args[dash]) != "npm" {
		return fmt.Errorf("scfw proxy: unsupported command %q: only npm is supported", args[dash])
	}
	return nil
}

func runProxy(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	httpStatus, err := cmd.Flags().GetInt("http-status")
	if err != nil {
		return fmt.Errorf("scfw proxy: read --http-status: %w", err)
	}
	command := args[cmd.ArgsLenAtDash():]
	executable, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("scfw proxy: find npm executable: %w", err)
	}

	if err := registryproxy.RunNPM(cmd.Context(), executable, command[1:], registryproxy.Streams{
		Stdin:  cmd.InOrStdin(),
		Stdout: cmd.OutOrStdout(),
		Stderr: cmd.ErrOrStderr(),
	}, registryproxy.Options{HTTPStatus: httpStatus}); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("scfw proxy: %w", err)
	}
	return nil
}
