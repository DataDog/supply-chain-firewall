// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/githook"
)

// newGitHookCmd is the command SCFW's git hook scripts run during scfw run.
// Git's hook arguments are passed through unparsed.
func newGitHookCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "git-hook",
		Hidden:             true,
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(githook.Run(cmd.Context(), args, os.Stdin, os.Stdout, os.Stderr))
		},
	}
}
