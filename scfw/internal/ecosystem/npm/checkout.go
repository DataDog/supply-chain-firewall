// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
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

// CheckoutPackage identifies the npm package in a git dependency checkout from
// its root package.json. Checkouts outside npm's temporary clone directories,
// and checkouts without a usable manifest, are not packages: npm fails on the
// latter by itself.
func CheckoutPackage(dir, origin, sha string) (pm.Package, bool, error) {
	if !strings.Contains(filepath.ToSlash(dir), gitCloneMarker) {
		return pm.Package{}, false, nil
	}
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
	if int64(len(manifest)) > archive.MaxMetadataBytes {
		return pm.Package{}, false, nil
	}
	artifact, found, err := parseManifest(manifest)
	if err != nil || !found {
		return pm.Package{}, false, nil
	}
	return pm.Package{
		Ecosystem: common.NPM, Name: artifact.Name, Version: artifact.Version,
		Source: redactGitRemote(origin) + "#" + sha,
	}, true, nil
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
