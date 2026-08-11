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

	"github.com/DataDog/scfw/scfw/internal/build"
)

var logLevels = map[string]slog.Level{
	"DEBUG":   slog.LevelDebug,
	"INFO":    slog.LevelInfo,
	"WARNING": slog.LevelWarn,
	"ERROR":   slog.LevelError,
}

var logLevel string

func RootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scfw",
		Short:   "Supply Chain Firewall, a tool for preventing the installation of malicious software packages.",
		Version: build.GetVersion(),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			level, ok := logLevels[logLevel]
			if !ok {
				return fmt.Errorf("invalid --log-level %q: must be one of %v", logLevel, slices.Sorted(maps.Keys(logLevels)))
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARNING", "Desired level for local logging")

	cmd.AddCommand(
		configureCmd,
		runCmd,
	)

	return cmd
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
