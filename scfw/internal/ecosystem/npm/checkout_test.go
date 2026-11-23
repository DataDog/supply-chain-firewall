// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

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

// cloneReflog is the HEAD reflog git clone writes.
const cloneReflog = "0000000000000000000000000000000000000000 abc A <a@b> 1700000000 +0000\tclone: from ssh://host/r.git\n"

func TestYarnCheckoutPackage(t *testing.T) {
	widget := pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}
	for _, test := range []struct {
		name, base, previous, reflog, manifest string
		want                                   pm.Package
		found                                  bool
	}{
		{name: "commit checkout", base: "xfs-0a1b2c3d", previous: "def", manifest: "manifest/widget.json", want: widget, found: true},
		// Checking out the commit the clone is already on still runs the hook,
		// whether or not a branch named after the commit keeps HEAD attached.
		{name: "same commit", base: "xfs-0a1b2c3d", previous: "abc", manifest: "manifest/widget.json", want: widget, found: true},
		{name: "no-version", base: "xfs-0a1b2c3d", previous: "def", manifest: "manifest/no-version.json",
			want: pm.Package{Ecosystem: common.NPM, Name: "widget", Source: "https://host/r.git#abc"}, found: true},
		// Yarn 4 never uses the default branch it clones before checking out the commit.
		{name: "clone checkout", base: "xfs-0a1b2c3d", previous: "0000000000000000000000000000000000000000", reflog: cloneReflog, manifest: "manifest/widget.json"},
		{name: "SHA-256 clone checkout", base: "xfs-0a1b2c3d", previous: "0000000000000000000000000000000000000000000000000000000000000000", reflog: cloneReflog, manifest: "manifest/widget.json"},
		// A clone of a remote whose HEAD names a missing branch checks nothing out,
		// so Yarn's checkout of the commit starts from an unborn HEAD.
		{name: "checkout from unborn HEAD", base: "xfs-0a1b2c3d", previous: "0000000000000000000000000000000000000000",
			reflog:   cloneReflog + "0000000000000000000000000000000000000000 abc A <a@b> 1700000000 +0000\tcheckout: moving from missing to abc\n",
			manifest: "manifest/widget.json", want: widget, found: true},
		{name: "zero previous without reflog", base: "xfs-0a1b2c3d", previous: "0000000000000000000000000000000000000000", manifest: "manifest/widget.json", want: widget, found: true},
		{name: "not a Yarn clone", base: "xfs-project", previous: "def", manifest: "manifest/widget.json"},
		// npm, which Yarn 4 runs to prepare npm repositories, clones their git
		// dependencies itself; each of its checkouts is evaluated.
		{name: "npm clone", base: filepath.Join("_cacache", "tmp", "git-cloneX"), previous: "0000000000000000000000000000000000000000", reflog: cloneReflog,
			manifest: "manifest/widget.json", want: widget, found: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), test.base)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(readNpmFixture(t, test.manifest)), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.reflog != "" {
				if err := os.MkdirAll(filepath.Join(dir, ".git", "logs"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".git", "logs", "HEAD"), []byte(test.reflog), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, found, err := YarnCheckoutPackage(dir, "https://u:tok@host/r.git", test.previous, "abc")
			if err != nil || found != test.found || got != test.want {
				t.Fatalf("YarnCheckoutPackage() = %+v, %v, %v; want %+v, %v", got, found, err, test.want, test.found)
			}
		})
	}
}

func TestYarnClassicArchivePackage(t *testing.T) {
	clone := "/cache/v6/.tmp/0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name, dir, sha string
		manifest       string
		readErr        error
		want           pm.Package
		found, wantErr bool
	}{
		{name: "clone", dir: clone, manifest: "manifest/widget.json",
			want: pm.Package{Ecosystem: common.NPM, Name: "@acme/widget", Version: "1.2.3", Source: "https://host/r.git#abc"}, found: true},
		{name: "not a Yarn clone", dir: "/project", manifest: "manifest/widget.json"},
		// Yarn Classic fails on a commit without a manifest by itself.
		{name: "no package.json", dir: clone, readErr: fs.ErrNotExist},
		{name: "unreadable", dir: clone, readErr: errors.New("git failed"), wantErr: true},
		{name: "unresolved commit", dir: clone, sha: "-", manifest: "manifest/widget.json", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sha := "abc"
			if test.sha == "-" {
				sha = ""
			}
			read := func(int64) ([]byte, error) {
				if test.readErr != nil {
					return nil, test.readErr
				}
				return []byte(readNpmFixture(t, test.manifest)), nil
			}
			got, found, err := YarnClassicArchivePackage(test.dir, "https://u:tok@host/r.git", sha, read)
			if (err != nil) != test.wantErr || found != test.found || got != test.want {
				t.Fatalf("YarnClassicArchivePackage() = %+v, %v, %v; want %+v, %v, error %v", got, found, err, test.want, test.found, test.wantErr)
			}
		})
	}
}
