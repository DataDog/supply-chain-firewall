// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package packagemanager

import (
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// PackageFromArtifactURL identifies a public npm, PyPI, or Maven Central artifact URL.
func PackageFromArtifactURL(rawURL string) (pm.Package, bool) {
	artifactURL, err := url.Parse(rawURL)
	if err != nil {
		return pm.Package{}, false
	}

	if pkg, ok := npmPackageFromArtifactURL(artifactURL); ok {
		return pkg, true
	}
	if pkg, ok := mavenPackageFromArtifactURL(artifactURL); ok {
		return pkg, true
	}
	return pyPIPackageFromArtifactURL(artifactURL)
}

func mavenPackageFromArtifactURL(artifactURL *url.URL) (pm.Package, bool) {
	if !ecosystem.HasRegistrySource(ecosystem.MAVEN, artifactURL.String()) {
		return pm.Package{}, false
	}

	parts := strings.Split(strings.Trim(artifactURL.Path, "/"), "/")
	if len(parts) > 0 && parts[0] == "maven2" {
		parts = parts[1:]
	}
	if len(parts) < 4 {
		return pm.Package{}, false
	}

	artifactID := parts[len(parts)-3]
	version := parts[len(parts)-2]
	filename := parts[len(parts)-1]
	extension := path.Ext(filename)
	if artifactID == "" || version == "" || !slices.Contains([]string{".aar", ".jar", ".klib", ".pom", ".war", ".zip"}, extension) {
		return pm.Package{}, false
	}

	base := strings.TrimSuffix(filename, extension)
	expectedPrefix := artifactID + "-" + version
	if versionBase, snapshot := strings.CutSuffix(version, "-SNAPSHOT"); snapshot {
		expectedPrefix = artifactID + "-" + versionBase
	}
	if base != expectedPrefix && !strings.HasPrefix(base, expectedPrefix+"-") {
		return pm.Package{}, false
	}

	groupParts := parts[:len(parts)-3]
	if slices.Contains(groupParts, "") {
		return pm.Package{}, false
	}
	name := strings.Join(groupParts, ".") + ":" + artifactID
	return pm.Package{Ecosystem: ecosystem.MAVEN, Name: name, Version: version, Source: artifactURL.String()}, true
}

func npmPackageFromArtifactURL(artifactURL *url.URL) (pm.Package, bool) {
	if !ecosystem.HasRegistrySource(ecosystem.NPM, artifactURL.String()) {
		return pm.Package{}, false
	}

	parts := strings.Split(strings.Trim(artifactURL.Path, "/"), "/")
	var name string
	var filename string
	switch {
	case len(parts) == 3 && parts[1] == "-":
		name = parts[0]
		filename = parts[2]
	case len(parts) == 4 && strings.HasPrefix(parts[0], "@") && parts[2] == "-":
		name = parts[0] + "/" + parts[1]
		filename = parts[3]
	default:
		return pm.Package{}, false
	}

	packageFilename := path.Base(name) + "-"
	if !strings.HasPrefix(filename, packageFilename) || !strings.HasSuffix(filename, ".tgz") {
		return pm.Package{}, false
	}
	version := strings.TrimSuffix(strings.TrimPrefix(filename, packageFilename), ".tgz")
	if version == "" {
		return pm.Package{}, false
	}

	return pm.Package{Ecosystem: ecosystem.NPM, Name: name, Version: version, Source: artifactURL.String()}, true
}

func pyPIPackageFromArtifactURL(artifactURL *url.URL) (pm.Package, bool) {
	if !ecosystem.HasRegistrySource(ecosystem.PYPI, artifactURL.String()) {
		return pm.Package{}, false
	}

	filename := path.Base(artifactURL.Path)
	name, version, ok := parsePythonDistributionFilename(filename)
	if !ok {
		return pm.Package{}, false
	}
	return pm.Package{Ecosystem: ecosystem.PYPI, Name: name, Version: version, Source: artifactURL.String()}, true
}

func parsePythonDistributionFilename(filename string) (string, string, bool) {
	if base, ok := strings.CutSuffix(filename, ".whl"); ok {
		parts := strings.Split(base, "-")
		if len(parts) < 5 || parts[0] == "" || parts[1] == "" {
			return "", "", false
		}
		return parts[0], parts[1], true
	}

	for _, extension := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".zip"} {
		base, ok := strings.CutSuffix(filename, extension)
		if !ok {
			continue
		}
		separator := strings.LastIndex(base, "-")
		if separator <= 0 || separator == len(base)-1 {
			return "", "", false
		}
		return base[:separator], base[separator+1:], true
	}
	return "", "", false
}
