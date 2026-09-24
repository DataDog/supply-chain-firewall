// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package packagemanager

import (
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestPackageFromArtifactURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want pm.Package
		ok   bool
	}{
		{
			name: "npm tarball",
			url:  "https://registry.npmjs.org/react-dom/-/react-dom-19.1.1.tgz",
			want: pm.Package{Ecosystem: ecosystem.NPM, Name: "react-dom", Version: "19.1.1", Source: "https://registry.npmjs.org/react-dom/-/react-dom-19.1.1.tgz"},
			ok:   true,
		},
		{
			name: "Yarn npm tarball",
			url:  "https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz",
			want: pm.Package{Ecosystem: ecosystem.NPM, Name: "is-number", Version: "7.0.0", Source: "https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz"},
			ok:   true,
		},
		{
			name: "scoped npm tarball",
			url:  "https://registry.npmjs.org/@scope/package/-/package-1.2.3.tgz",
			want: pm.Package{Ecosystem: ecosystem.NPM, Name: "@scope/package", Version: "1.2.3", Source: "https://registry.npmjs.org/@scope/package/-/package-1.2.3.tgz"},
			ok:   true,
		},
		{
			name: "PyPI wheel",
			url:  "https://files.pythonhosted.org/packages/hash/typing_extensions-4.12.2-py3-none-any.whl",
			want: pm.Package{Ecosystem: ecosystem.PYPI, Name: "typing_extensions", Version: "4.12.2", Source: "https://files.pythonhosted.org/packages/hash/typing_extensions-4.12.2-py3-none-any.whl"},
			ok:   true,
		},
		{
			name: "PyPI source distribution",
			url:  "https://files.pythonhosted.org/packages/hash/charset-normalizer-3.4.2.tar.gz",
			want: pm.Package{Ecosystem: ecosystem.PYPI, Name: "charset-normalizer", Version: "3.4.2", Source: "https://files.pythonhosted.org/packages/hash/charset-normalizer-3.4.2.tar.gz"},
			ok:   true,
		},
		{
			name: "Maven Central JAR",
			url:  "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar",
			want: pm.Package{Ecosystem: ecosystem.MAVEN, Name: "org.apache.commons:commons-lang3", Version: "3.17.0", Source: "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar"},
			ok:   true,
		},
		{
			name: "Maven Central classified POM",
			url:  "https://repo1.maven.org/maven2/com/example/tool/1.2.3/tool-1.2.3-tests.pom",
			want: pm.Package{Ecosystem: ecosystem.MAVEN, Name: "com.example:tool", Version: "1.2.3", Source: "https://repo1.maven.org/maven2/com/example/tool/1.2.3/tool-1.2.3-tests.pom"},
			ok:   true,
		},
		{
			name: "Maven Central timestamped snapshot",
			url:  "https://repo.maven.apache.org/maven2/com/example/tool/1.2-SNAPSHOT/tool-1.2-20260923.120000-1.jar",
			want: pm.Package{Ecosystem: ecosystem.MAVEN, Name: "com.example:tool", Version: "1.2-SNAPSHOT", Source: "https://repo.maven.apache.org/maven2/com/example/tool/1.2-SNAPSHOT/tool-1.2-20260923.120000-1.jar"},
			ok:   true,
		},
		{name: "npm metadata", url: "https://registry.npmjs.org/react"},
		{name: "PyPI metadata sidecar", url: "https://files.pythonhosted.org/packages/hash/idna-3.10-py3-none-any.whl.metadata"},
		{name: "Maven metadata", url: "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml"},
		{name: "Maven checksum", url: "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.sha1"},
		{name: "non-matching Maven filename", url: "https://repo.maven.apache.org/maven2/com/example/tool/1.0.0/other-1.0.0.jar"},
		{name: "unrelated archive", url: "https://example.com/react-19.1.1.tgz"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := PackageFromArtifactURL(test.url)
			if ok != test.ok || got != test.want {
				t.Errorf("PackageFromArtifactURL(%q) = (%#v, %v), want (%#v, %v)", test.url, got, ok, test.want, test.ok)
			}
		})
	}
}
