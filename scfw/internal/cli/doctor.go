// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"errors"
	"fmt"
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
	// Installation and configuration checks will be added here.
	apiKey, appKey, apiKeyCredentialSource, appKeyCredentialSource, credentialErr := ddapi.DDCredentials()

	if credentialErr != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "❌ Credentials not found with an error : %v\n", credentialErr)
	} else {
		if len(apiKey) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "❌ API Key not found in keychain nor environment")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "✅ API Key found in %s\n", apiKeyCredentialSource)
		}
		if len(appKey) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "❌ Application Key not found in keychain nor environment")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "✅ Application Key found in %s\n", appKeyCredentialSource)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return errors.Join(credentialErr, fmt.Errorf("could not locate shell configuration: %w", err))
	}

	if aliasErr := reportAliases(cmd, home); aliasErr != nil {
		return errors.Join(credentialErr, aliasErr)
	}

	return credentialErr
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

	return errors.Join(errs...)
}
