// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"net/url"
	"testing"
)

func TestPackageFromTarballURL(t *testing.T) {
	destination, _ := url.Parse("https://registry.example/@scope/pkg/-/pkg-1.2.3.tgz")
	pkg, ok := (Handler{}).Package(destination)
	if !ok {
		t.Fatal("Package() did not recognize npm tarball")
	}
	if pkg.Name != "@scope/pkg" || pkg.Version != "1.2.3" {
		t.Errorf("Package() = %+v", pkg)
	}
}
