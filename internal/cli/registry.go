// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"slices"

	"github.com/DataDog/scfw/scfw/internal/pm"
	"github.com/DataDog/scfw/scfw/internal/pm/npm"
	"github.com/DataDog/scfw/scfw/internal/pm/pip"
	"github.com/DataDog/scfw/scfw/internal/pm/poetry"
)

type PackageManagerFactory struct {
	Names []string
	New   func(ctx context.Context, name, executable string) (pm.PackageManager, error)
}

var packageManagerFactories = []PackageManagerFactory{
	{
		Names: npm.NpmExecutableNames,
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return npm.NewNpm(ctx, name, executable)
		},
	},
	{
		Names: pip.PipExecutableNames,
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return pip.NewPip(ctx, name, executable)
		},
	},
	{
		Names: poetry.PoetryExecutableNames,
		New: func(ctx context.Context, name, executable string) (pm.PackageManager, error) {
			return poetry.NewPoetry(ctx, name, executable)
		},
	},
}

func findPackageManagerFactory(name string) (PackageManagerFactory, bool) {
	for _, factory := range packageManagerFactories {
		if slices.Contains(factory.Names, name) {
			return factory, true
		}
	}
	return PackageManagerFactory{}, false
}
