// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// pnpm clones git dependencies into the store's tmp directory (pnpm 10 and
// 11) or a Rust-style temporary directory (pnpm 12), and every clone is
// evaluated even when its root package.json is missing or invalid, because a
// path: subdirectory can still be installed.
func TestCheckoutPackagePnpmClone(t *testing.T) {
	oversized := `{"name":"widget","version":"1.0.0","pad":"` + strings.Repeat("x", int(archive.MaxMetadataBytes)) + `"}`
	widget := readNpmFixture(t, "manifest/widget.json")
	for _, test := range []struct {
		name, manifest, dir string
		inTempDirectory     bool
		want                pm.Package
		found, wantErr      bool
	}{
		{name: "store v10 clone", dir: filepath.Join("store", "v10", "tmp", "_tmp_62677_5ca30b09709be2826975da7afce590e"), manifest: widget,
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		{name: "store v11 clone", dir: filepath.Join("store", "v11", "tmp", "_tmp_kw2RDy"), manifest: widget,
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		{name: "missing manifest", dir: filepath.Join("store", "v10", "tmp", "_tmp_1"),
			want: pm.Package{Ecosystem: common.NPM, Source: "https://host/r.git#abc"}, found: true},
		{name: "invalid manifest", dir: filepath.Join("store", "v10", "tmp", "_tmp_1"), manifest: readNpmFixture(t, "manifest/invalid.json"),
			want: pm.Package{Ecosystem: common.NPM, Source: "https://host/r.git#abc"}, found: true},
		{name: "tmp sibling without the clone prefix", dir: filepath.Join("store", "v10", "tmp", "clone"), manifest: widget},
		{name: "_tmp_ outside a tmp directory", dir: filepath.Join("store", "v10", "other", "_tmp_1"), manifest: widget},
		{name: "pnpm 12 temporary clone", dir: ".tmpAbC123", inTempDirectory: true, manifest: widget,
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		{name: "pnpm 12 clone without a manifest", dir: ".tmpQw9Xy", inTempDirectory: true,
			want: pm.Package{Ecosystem: common.NPM, Source: "https://host/r.git#abc"}, found: true},
		{name: "pnpm 12 pattern outside the temporary directory", dir: ".tmpAbC123", manifest: widget},
		{name: "pnpm 12 pattern with a non-tempfile name", dir: ".tmp-cache", inTempDirectory: true, manifest: widget},
		{name: "oversized manifest", dir: filepath.Join("store", "v10", "tmp", "_tmp_1"), manifest: oversized, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), test.dir)
			if test.inTempDirectory {
				dir = filepath.Join(os.TempDir(), test.dir)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.inTempDirectory {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
			}
			if test.manifest != "" {
				if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(test.manifest), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, found, err := CheckoutPackage(dir, "https://host/r.git", "abc")
			if (err != nil) != test.wantErr {
				t.Fatalf("CheckoutPackage() error = %v, want error %v", err, test.wantErr)
			}
			if found != test.found || got != test.want {
				t.Fatalf("CheckoutPackage() = %+v, %v; want %+v, %v", got, found, test.want, test.found)
			}
		})
	}
}

func TestCheckoutPackage(t *testing.T) {
	oversized := `{"name":"widget","version":"1.0.0","pad":"` + strings.Repeat("x", int(archive.MaxMetadataBytes)) + `"}`
	for _, test := range []struct {
		name, manifest, origin string
		notClone               bool
		want                   pm.Package
		found                  bool
		wantErr                bool
	}{
		{name: "widget", manifest: readNpmFixture(t, "manifest/widget.json"), origin: "https://host/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		{name: "v-prefixed", manifest: readNpmFixture(t, "manifest/v-prefixed.json"), origin: "https://host/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		// npm installs these and runs their lifecycle scripts, so each is evaluated
		// with the identity it declares.
		{name: "no-version", manifest: readNpmFixture(t, "manifest/no-version.json"), origin: "https://host/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "widget", Version: "", Source: "https://host/r.git#abc"}, found: true},
		{name: "loose-only version", manifest: readNpmFixture(t, "manifest/loose-version.json"), origin: "https://host/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "widget", Version: "01.0.0", Source: "https://host/r.git#abc"}, found: true},
		{name: "no-name", manifest: readNpmFixture(t, "manifest/no-name.json"), origin: "https://host/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		// npm fails on these by itself.
		{name: "no package.json", origin: "https://host/r.git"},
		{name: "invalid manifest", manifest: readNpmFixture(t, "manifest/invalid.json"), origin: "https://host/r.git"},
		{name: "not a temporary clone", manifest: readNpmFixture(t, "manifest/widget.json"), origin: "https://host/r.git", notClone: true},
		{name: "https credentials", manifest: readNpmFixture(t, "manifest/widget.json"), origin: "https://u:tok@host/r.git?x=1",
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		{name: "ssh credentials", manifest: readNpmFixture(t, "manifest/widget.json"), origin: "ssh://git:pw@host/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "ssh://host/r.git#abc"}, found: true},
		{name: "scp-like remote", manifest: readNpmFixture(t, "manifest/widget.json"), origin: "git@host:o/r.git",
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "host:o/r.git#abc"}, found: true},
		// npm has no size limit, so an oversized manifest cannot be allowed unread.
		{name: "oversized manifest", manifest: oversized, origin: "https://host/r.git", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "_cacache", "tmp", "git-cloneX")
			if test.notClone {
				dir = filepath.Join(t.TempDir(), "project")
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.manifest != "" {
				if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(test.manifest), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, found, err := CheckoutPackage(dir, test.origin, "abc")
			if (err != nil) != test.wantErr {
				t.Fatalf("CheckoutPackage() error = %v, want error %v", err, test.wantErr)
			}
			if found != test.found || got != test.want {
				t.Fatalf("CheckoutPackage() = %+v, %v; want %+v, %v", got, found, test.want, test.found)
			}
		})
	}
}
