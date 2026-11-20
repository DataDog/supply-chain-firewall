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
	"regexp"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// pacote clones every git dependency into a temporary directory of npm's cache.
const gitCloneMarker = "/_cacache/tmp/git-clone"

// Yarn 4 clones every git dependency into a new xfs temporary directory.
var yarnCloneName = regexp.MustCompile(`^xfs-[0-9a-f]{8}$`)

// CheckoutPackage identifies the npm package in a git dependency checkout from
// its root package.json. Checkouts outside npm's temporary clone directories
// are not packages, and neither are checkouts whose package.json is missing or
// invalid JSON: npm fails on those by itself. npm installs a manifest without a
// usable name or version and runs its lifecycle scripts, so that manifest is
// identified by what it declares, possibly empty.
func CheckoutPackage(dir, origin, sha string) (pm.Package, bool, error) {
	if !strings.Contains(filepath.ToSlash(dir), gitCloneMarker) {
		return pm.Package{}, false, nil
	}
	return checkoutPackage(dir, origin, sha)
}

// YarnCheckoutPackage identifies the package in a Yarn 4 git dependency
// checkout like CheckoutPackage. Yarn 4 clones the default branch and then
// checks out the dependency's commit, detaching HEAD; it never uses the branch
// checkout, so only the detached one is a package.
func YarnCheckoutPackage(dir, origin, sha string) (pm.Package, bool, error) {
	if !yarnCloneName.MatchString(filepath.Base(dir)) {
		return pm.Package{}, false, nil
	}
	head, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD"))
	if err != nil {
		return pm.Package{}, false, err
	}
	if bytes.HasPrefix(head, []byte("ref: ")) {
		return pm.Package{}, false, nil
	}
	return checkoutPackage(dir, origin, sha)
}

func checkoutPackage(dir, origin, sha string) (pm.Package, bool, error) {
	file, err := os.Open(filepath.Join(dir, "package.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return pm.Package{}, false, nil
	}
	if err != nil {
		return pm.Package{}, false, err
	}
	defer func() { _ = file.Close() }()
	manifest, err := io.ReadAll(io.LimitReader(file, archive.MaxMetadataBytes+1))
	if err != nil {
		return pm.Package{}, false, err
	}
	return manifestPackage(manifest, origin, sha)
}

func manifestPackage(manifest []byte, origin, sha string) (pm.Package, bool, error) {
	// npm has no size limit, so a manifest that cannot be read in full is not
	// allowed unevaluated.
	if int64(len(manifest)) > archive.MaxMetadataBytes {
		return pm.Package{}, false, errors.New("the checkout's package.json exceeds the inspection limit")
	}
	artifact, found, err := parseManifest(manifest)
	if err != nil {
		return pm.Package{}, false, nil
	}
	if !found {
		artifact.Name, artifact.Version = declaredIdentity(manifest)
	}
	return pm.Package{
		Ecosystem: common.NPM, Name: artifact.Name, Version: artifact.Version,
		Source: redactGitRemote(origin) + "#" + sha,
	}, true, nil
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
