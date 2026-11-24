// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// pacote clones every git dependency into a temporary directory of npm's cache.
const gitCloneMarker = "/_cacache/tmp/git-clone"

// CheckoutPackage identifies the npm or pnpm package in a git dependency
// checkout from its root package.json. Checkouts outside the managers'
// temporary clone directories are not packages. An npm checkout whose
// package.json is missing or invalid JSON is not a package either: npm fails
// on those by itself. A pnpm checkout always identifies a package, with an
// empty name and version when its root package.json is missing or invalid,
// because pnpm can install a path: subdirectory whose root manifest is not
// usable; every clone still gets a decision. A manifest without a usable name
// or version is identified by what it declares, possibly empty.
func CheckoutPackage(dir, origin, sha string) (pm.Package, bool, error) {
	npmClone := strings.Contains(filepath.ToSlash(dir), gitCloneMarker)
	pnpmClone := !npmClone && isPnpmClone(dir)
	if !npmClone && !pnpmClone {
		return pm.Package{}, false, nil
	}
	pkg := pm.Package{Ecosystem: common.NPM, Source: redactGitRemote(origin) + "#" + sha}
	file, err := os.Open(filepath.Join(dir, "package.json"))
	if errors.Is(err, fs.ErrNotExist) {
		if !pnpmClone {
			return pm.Package{}, false, nil
		}
		return pkg, true, nil
	}
	if err != nil {
		return pm.Package{}, false, err
	}
	defer func() { _ = file.Close() }()
	manifest, err := io.ReadAll(io.LimitReader(file, archive.MaxMetadataBytes+1))
	if err != nil {
		return pm.Package{}, false, err
	}
	// npm has no size limit, so a manifest that cannot be read in full is not
	// allowed unevaluated.
	if int64(len(manifest)) > archive.MaxMetadataBytes {
		return pm.Package{}, false, errors.New("the checkout's package.json exceeds the inspection limit")
	}
	artifact, found, err := parseManifest(manifest)
	if err != nil {
		if !pnpmClone {
			return pm.Package{}, false, nil
		}
		return pkg, true, nil
	}
	if !found {
		artifact.Name, artifact.Version = declaredIdentity(manifest)
	}
	pkg.Name, pkg.Version = artifact.Name, artifact.Version
	return pkg, true, nil
}

// isPnpmClone reports whether dir is a temporary clone directory of a pnpm
// git dependency. pnpm 10 and 11 clone into the store's tmp directory, whose
// entries are named _tmp_* whatever the store location and version are, and
// pnpm 12 clones into a .tmp* directory of the system temporary directory.
func isPnpmClone(dir string) bool {
	name := filepath.Base(dir)
	if filepath.Base(filepath.Dir(dir)) == "tmp" && strings.HasPrefix(name, "_tmp_") {
		return true
	}
	// pnpm 12 names its Rust tempfile clone .tmp plus random letters and
	// digits; the parent must be the temporary directory, whose name may
	// resolve differently in the hook process than in this one.
	suffix, named := strings.CutPrefix(name, ".tmp")
	if !named || suffix == "" {
		return false
	}
	for _, character := range suffix {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", character) {
			return false
		}
	}
	parent, err := os.Stat(filepath.Dir(dir))
	if err != nil {
		return false
	}
	temp, err := os.Stat(os.TempDir())
	return err == nil && os.SameFile(parent, temp)
}

// declaredIdentity returns the name and version a manifest declares, however
// npm would normalize them, and empty strings for anything that is not a string.
func declaredIdentity(manifest []byte) (name, version string) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimPrefix(manifest, []byte("\xef\xbb\xbf")), &fields) != nil {
		return "", ""
	}
	_ = json.Unmarshal(fields["name"], &name)
	_ = json.Unmarshal(fields["version"], &version)
	return name, strings.TrimSpace(version)
}

// redactGitRemote removes credentials from a git remote, including scp-like
// "user@host:path" remotes that url.Parse does not accept.
func redactGitRemote(origin string) string {
	if strings.Contains(origin, "://") {
		parsed, err := url.Parse(origin)
		if err != nil {
			return "[REDACTED_URL]"
		}
		return redactURL(parsed)
	}
	host, _, _ := strings.Cut(origin, ":")
	if at := strings.LastIndex(host, "@"); at >= 0 {
		return origin[at+1:]
	}
	return origin
}
