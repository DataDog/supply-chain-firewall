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
	apiKeyReportErr := reportCredential(cmd.OutOrStdout(), "API Key", apiKey, apiKeyCredentialSource, apiKeyErr)
	appKeyReportErr := reportCredential(cmd.OutOrStdout(), "Application Key", appKey, appKeyCredentialSource, appKeyErr)
	credentialErr := errors.Join(apiKeyErr, appKeyErr)
	reportErr := errors.Join(apiKeyReportErr, appKeyReportErr)

	home, err := os.UserHomeDir()
	if err != nil {
		return errors.Join(credentialErr, reportErr, fmt.Errorf("could not locate shell configuration: %w", err))
	}

	if aliasErr := reportAliases(cmd, home); aliasErr != nil {
		return errors.Join(credentialErr, reportErr, aliasErr)
	}

	return errors.Join(credentialErr, reportErr)
}

func reportCredential(out io.Writer, name, value string, source ddapi.CredentialSource, err error) error {
	if err != nil {
		_, writeErr := fmt.Fprintf(out, "❌ %s not found: %v\n", name, err)
		return writeErr
	}
	if value == "" {
		_, writeErr := fmt.Fprintf(out, "❌ %s not found in keychain nor environment\n", name)
		return writeErr
	}
	_, writeErr := fmt.Fprintf(out, "✅ %s found in %s\n", name, source)
	return writeErr
}

var availableAliases = []string{"npm", "pip", "pip3", "poetry"}

type invalidAlias struct {
	path   string
	target string
}

func expectedAliasTarget(name string) string {
	return "scfw run -- " + name
}

// reportAliases reports whether every alias supported by scfw configure is
// present in SCFW's managed block, targets SCFW, and lists each shell config
// that correctly defines it.
func reportAliases(cmd *cobra.Command, home string) error {
	aliasLocations := make(map[string][]string)
	invalidAliases := make(map[string][]invalidAlias)
	var errs []error

	for _, configFile := range configFiles {
		path := filepath.Join(home, configFile)
		aliases, err := readManagedBlock(path)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️ Could not read aliases from %s: %v\n", path, err)
			errs = append(errs, err)
			continue
		}
		for name, target := range aliases {
			if target != expectedAliasTarget(name) {
				invalidAliases[name] = append(invalidAliases[name], invalidAlias{path: path, target: target})
				continue
			}
			aliasLocations[name] = append(aliasLocations[name], path)
		}
	}

	for _, name := range availableAliases {
		locations := aliasLocations[name]
		invalid := invalidAliases[name]
		if len(locations) == 0 && len(invalid) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "❌ Alias %s is not set\n", name)
			continue
		}
		if len(locations) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "✅ Alias %s is set in %s\n", name, strings.Join(locations, ", "))
		}
		for _, alias := range invalid {
			fmt.Fprintf(
				cmd.OutOrStdout(),
				"❌ Alias %s in %s targets %q; expected %q\n",
				name,
				alias.path,
				alias.target,
				expectedAliasTarget(name),
			)
		}
	}
	aliasNames := strings.Join(availableAliases, " ")
	fmt.Fprintf(
		cmd.OutOrStdout(),
		"ℹ️ Run `alias %s` to check which aliases are active in the current terminal. If an alias configured above is not found, reload your terminal.\n",
		aliasNames,
	)

	return errors.Join(errs...)
}
