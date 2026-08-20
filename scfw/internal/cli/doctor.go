// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the Supply Chain Firewall installation and configuration.",
	Args:  cobra.NoArgs,
	RunE:  runDoctor,
}

func runDoctor(cmd *cobra.Command, args []string) error {
	apiKey, apiKeyCredentialSource, apiKeyErr := ddapi.ResolveDatadogAPIKey()
	appKey, appKeyCredentialSource, appKeyErr := ddapi.ResolveDatadogAppKey()
	reportCredential(cmd.OutOrStdout(), "API Key", apiKey, apiKeyCredentialSource, apiKeyErr)
	reportCredential(cmd.OutOrStdout(), "Application Key", appKey, appKeyCredentialSource, appKeyErr)
	credentialErr := errors.Join(apiKeyErr, appKeyErr)

	home, err := os.UserHomeDir()
	if err != nil {
		return errors.Join(credentialErr, fmt.Errorf("could not locate shell configuration: %w", err))
	}

	if aliasErr := reportAliases(cmd, home); aliasErr != nil {
		return errors.Join(credentialErr, aliasErr)
	}

	return credentialErr
}

func reportCredential(out io.Writer, name, value string, source ddapi.CredentialSource, err error) {
	if err != nil {
		fmt.Fprintf(out, "❌ %s not found: %v\n", name, err)
		return
	}
	if value == "" {
		fmt.Fprintf(out, "❌ %s not found in keychain nor environment\n", name)
		return
	}
	fmt.Fprintf(out, "✅ %s found in %s\n", name, source)
}

var availableAliases = []string{"npm", "pip", "pip3", "poetry"}

// reportAliases reports whether every alias supported by scfw configure is
// present in SCFW's managed block and lists each shell config that defines it.
func reportAliases(cmd *cobra.Command, home string) error {
	aliasLocations := make(map[string][]string)
	var errs []error

	for _, configFile := range configFiles {
		path := filepath.Join(home, configFile)
		aliases, err := readManagedBlock(path)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️ Could not read aliases from %s: %v\n", path, err)
			errs = append(errs, err)
			continue
		}
		for name := range aliases {
			aliasLocations[name] = append(aliasLocations[name], path)
		}
	}

	for _, name := range availableAliases {
		locations := aliasLocations[name]
		if len(locations) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "❌ Alias %s is not set\n", name)
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✅ Alias %s is set in %s\n", name, strings.Join(locations, ", "))
	}
	aliasNames := strings.Join(availableAliases, " ")
	fmt.Fprintf(
		cmd.OutOrStdout(),
		"ℹ️ Run `alias %s` to check which aliases are active in the current terminal. If an alias configured above is not found, reload your terminal.\n",
		aliasNames,
	)

	return errors.Join(errs...)
}
