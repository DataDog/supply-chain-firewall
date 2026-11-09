// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"slices"
	"testing"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
)

func TestNpmClassifierOptionsListsConfiguredRegistries(t *testing.T) {
	t.Run("defaults to the public registry", func(t *testing.T) {
		manager := isolatedNpm(t)
		options, err := manager.NpmClassifierOptions([]string{"install"})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"https://registry.npmjs.org/"}; !slices.Equal(options.RegistryURLs, want) {
			t.Fatalf("registries = %q, want %q", options.RegistryURLs, want)
		}
	})
	t.Run("configured and scoped registries", func(t *testing.T) {
		manager := isolatedNpm(t)
		writeNpmFixture(t, ".npmrc", "registry=https://art.test/api/npm/npm/\n"+
			"@lab:registry=https://art.test/api/npm/lab/\n@dup:registry=https://art.test/api/npm/npm/\n"+
			"@bad:registry=not a url\n@ftp:registry=ftp://x/\n@hostless:registry=https:///\n")
		options, err := manager.NpmClassifierOptions([]string{"install", "--@other:registry=https://o.test/"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"https://art.test/api/npm/npm/", "https://art.test/api/npm/lab/", "https://o.test/"}
		if !slices.Equal(options.RegistryURLs, want) {
			t.Fatalf("registries = %q, want %q", options.RegistryURLs, want)
		}
		if _, err := npmregistry.NewClassifier(options); err != nil {
			t.Fatalf("classifier rejected the registries: %v", err)
		}
	})
}
