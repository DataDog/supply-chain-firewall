// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"fmt"

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
	apiKey, appKey, apiKeyCredentialSource, appKeyCredentialSource, err := ddapi.DDCredentials()

	if err != nil {
		fmt.Printf("❌ Credentials not found with an error : %v\n", err)
	} else {
		if len(apiKey) == 0 {
			fmt.Printf("❌ API Key not found in keychain nor environment\n")
		} else {
			fmt.Printf("✅ API Key found in %s\n", apiKeyCredentialSource)
		}
		if len(appKey) == 0 {
			fmt.Printf("❌ Application Key not found in keychain nor environment\n")
		} else {
			fmt.Printf("✅ Application Key found in %s\n", appKeyCredentialSource)
		}
	}
	return err
}
