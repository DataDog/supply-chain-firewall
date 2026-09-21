// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package pnpm owns pnpm registry discovery and process-local overrides.
package pnpm

import (
	"context"
	"encoding/json"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	npmecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
)

type Manager struct{}

func (Manager) Name() string { return "pnpm" }

func (Manager) Registries(ctx context.Context, executable string, _ []string) (proxy.RegistryConfiguration, error) {
	output, err := shared.CommandOutput(ctx, executable, "config", "list", "--json")
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	registry, named, err := shared.ParseNPMJSON(output)
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	var values map[string]json.RawMessage
	_ = json.Unmarshal(output, &values)
	var caFile string
	_ = json.Unmarshal(values["cafile"], &caFile)
	var caCertificates []string
	if json.Unmarshal(values["ca"], &caCertificates) != nil {
		var certificate string
		if json.Unmarshal(values["ca"], &certificate) == nil && certificate != "" {
			caCertificates = []string{certificate}
		}
	}
	var strictSSL *bool
	_ = json.Unmarshal(values["strict-ssl"], &strictSSL)
	return proxy.RegistryConfiguration{
		Default: registry, Named: named, Handler: npmecosystem.Handler{}, UseNPMCredentials: true,
		CAFile: caFile, CACertificates: caCertificates,
		InsecureTLS: strictSSL != nil && !*strictSSL,
	}, nil
}

func (Manager) Prepare(_ string, args []string, registryURL string, named map[string]string) (proxy.PreparedCommand, error) {
	options := []string{"--registry=" + registryURL}
	positionals := shared.PositionalArguments(args, pnpmOptionsWithValue)
	if pnpmInstallOperation(positionals) {
		options = append(options, "--frozen-lockfile")
	}
	options = append(options, shared.SortedNamedOptions(named, func(name, value string) string {
		return "--" + name + ":registry=" + value
	})...)
	return proxy.PreparedCommand{Args: shared.InsertOptions(args, options)}, nil
}

var pnpmOptionsWithValue = map[string]bool{
	"--config-dir":            true,
	"--dir":                   true,
	"--filter":                true,
	"--global-bin-dir":        true,
	"--global-dir":            true,
	"--package-import-method": true,
	"--registry":              true,
	"--reporter":              true,
	"--state-dir":             true,
	"--store-dir":             true,
	"--virtual-store-dir":     true,
	"--workspace-concurrency": true,
	"-c":                      true,
	"-f":                      true,
}

func pnpmInstallOperation(positionals []string) bool {
	if len(positionals) == 0 {
		return false
	}
	switch positionals[0] {
	case "install", "i", "install-test", "it":
		return true
	case "recursive":
		if len(positionals) < 2 {
			return false
		}
		switch positionals[1] {
		case "install", "i", "install-test", "it":
			return true
		}
	}
	return false
}
