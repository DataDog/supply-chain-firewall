// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/build"
)

var logLevels = map[string]slog.Level{
	"DEBUG":   slog.LevelDebug,
	"INFO":    slog.LevelInfo,
	"WARNING": slog.LevelWarn,
	"ERROR":   slog.LevelError,
}

var logLevel string

const verboseEnvVar = "SCFW_VERBOSE"

func RootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scfw",
		Short: "Supply Chain Firewall is a Datadog tool that prevents the installation of malicious software packages.",
		Long: `Supply Chain Firewall is a Datadog tool that prevents the installation of malicious software packages.

Set SCFW_VERBOSE to enable detailed progress and diagnostic logging.`,
		Example: `  scfw configure --dd-api-key=<your-api-key> --dd-app-key=<your-app-key> --alias-npm --alias-pip --alias-poetry
  scfw run -- npm install react
  scfw run -- pip install requests`,
		Version: build.GetVersion(),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return configureLogging(logLevel)
		},
	}

	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARNING", "Desired level for local logging")

	cmd.AddCommand(
		configureCmd,
		runCmd,
	)

	return cmd
}

func configureLogging(logLevel string) error {
	level, ok := logLevels[logLevel]
	if !ok {
		return fmt.Errorf("invalid --log-level %q: must be one of %v", logLevel, slices.Sorted(maps.Keys(logLevels)))
	}
	if os.Getenv(verboseEnvVar) != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}

// Raises error if any of cmd's string flags was given a value starting with "--",
// which almost certainly means a missing value swallowed the next flag given.
func rejectFlagLikeValues(cmd *cobra.Command) error {
	var err error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if err == nil && f.Changed && f.Value.Type() == "string" && strings.HasPrefix(f.Value.String(), "--") {
			err = fmt.Errorf("%s: flag --%s was given a value that looks like another flag: %q", cmd.CommandPath(), f.Name, f.Value.String())
		}
	})
	return err
}
