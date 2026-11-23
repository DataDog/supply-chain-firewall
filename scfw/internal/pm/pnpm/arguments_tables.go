// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

// The option types of pnpm's command-selecting parse (global, add, and install
// options), generated from each release's nopt type tables, and the built-in
// command tables the proxy selection is inverted from (pnpm 10.34.9's
// pnpm/src/cmd/index.ts plus the npm pass-through in pnpm/src/pnpm.ts, 11.28.9's
// pnpm11/pnpm/src/cmd/index.ts, and 12.18.0's clap grammar, with the pnpm 12.23
// additions catalog and fund).

var nopt10 = noptOptions{
	values:     []string{"allow-build", "changed-files-ignore-pattern", "child-concurrency", "cpu", "fetch-retries", "fetch-retry-factor", "fetch-retry-maxtimeout", "fetch-retry-mintimeout", "fetch-timeout", "filter", "filter-prod", "hoist-pattern", "https-proxy", "libc", "loglevel", "merge-git-branch-lockfiles-branch-pattern", "network-concurrency", "node-linker", "only", "os", "package-import-method", "prefix", "proxy", "public-hoist-pattern", "registry", "scripts-prepend-node-path", "test-pattern", "trust-policy", "trust-policy-exclude", "trust-policy-ignore-after", "workspace-packages"},
	strings:    []string{"cache-dir", "dir", "global-bin-dir", "global-dir", "global-pnpmfile", "lockfile-dir", "lockfile-directory", "modules-dir", "noproxy", "npm-path", "pnpmfile", "reporter", "save-catalog-name", "save-prefix", "store-dir", "virtual-store-dir"},
	flags:      []string{"aggregate-output", "config", "dangerously-allow-all-builds", "dev", "engine-strict", "fail-if-no-match", "fix-lockfile", "force", "frozen-lockfile", "global", "help", "hoist", "ignore-pnpmfile", "ignore-scripts", "ignore-workspace", "ignore-workspace-root-check", "include-workspace-root", "lockfile", "lockfile-only", "merge-git-branch-lockfiles", "offline", "optimistic-repeat-install", "optional", "parseable", "prefer-frozen-lockfile", "prefer-offline", "production", "recursive", "resolution-only", "save", "save-dev", "save-exact", "save-optional", "save-peer", "save-prod", "save-workspace-protocol", "shamefully-flatten", "shamefully-hoist", "shared-workspace-lockfile", "side-effects-cache", "side-effects-cache-readonly", "stream", "strict-peer-dependencies", "unsafe-perm", "update-checksums", "use-running-store-server", "use-stderr", "use-store-server", "verify-store-integrity", "workspace", "workspace-root"},
	enums:      map[string][]string{"color": {"always"}, "link-workspace-packages": {"deep"}},
	shorthands: map[string]string{"?": "--help", "C": "--dir", "D": "--save-dev", "E": "--save-exact", "F": "--filter", "H": "--help", "L": "--latest", "O": "--save-optional", "P": "--save-prod", "S": "--save", "d": "--loglevel=info", "dd": "--loglevel=verbose", "ddd": "--loglevel=silly", "development": "--dev", "f": "--force", "g": "--global", "h": "--help", "i": "--interactive", "l": "--long", "local": "--no-global", "p": "--parseable", "porcelain": "--parseable", "prod": "--production", "q": "--loglevel=warn", "quiet": "--loglevel=warn", "r": "--recursive", "s": "--reporter=silent", "silent": "--reporter=silent", "usage": "--help", "v": "--version", "verbose": "--loglevel=verbose", "w": "--workspace-root"},
	aliases:    map[string]string{"c": "config", "clean-install": "ci", "dislink": "unlink", "i": "install", "ic": "ci", "install-clean": "ci", "it": "install-test", "la": "ll", "ln": "link", "ls": "list", "m": "recursive", "multi": "recursive", "rb": "rebuild", "rm": "remove", "run-script": "run", "un": "remove", "uni": "remove", "uninstall": "remove", "up": "update", "upgrade": "update"},
}

var nopt11 = noptOptions{
	values:     []string{"allow-build", "changed-files-ignore-pattern", "child-concurrency", "cpu", "fetch-retries", "fetch-retry-factor", "fetch-retry-maxtimeout", "fetch-retry-mintimeout", "fetch-timeout", "filter", "filter-prod", "hoist-pattern", "hoisting-limits", "https-proxy", "libc", "loglevel", "merge-git-branch-lockfiles-branch-pattern", "network-concurrency", "node-linker", "node-package-map-type", "only", "os", "package-import-method", "pm-on-fail", "pnpr-server", "prefix", "proxy", "public-hoist-pattern", "registry", "scripts-prepend-node-path", "test-pattern", "trust-policy", "trust-policy-exclude", "trust-policy-ignore-after", "workspace-packages"},
	strings:    []string{"cache-dir", "dir", "global-bin-dir", "global-dir", "global-pnpmfile", "lockfile-dir", "modules-dir", "noproxy", "npm-path", "pnpmfile", "reporter", "save-catalog-name", "save-prefix", "store-dir", "virtual-store-dir"},
	flags:      []string{"aggregate-output", "config", "dangerously-allow-all-builds", "dev", "dry-run", "engine-strict", "fail-if-no-match", "fix-lockfile", "force", "frozen-lockfile", "frozen-store", "global", "help", "hoist", "ignore-pnpmfile", "ignore-scripts", "ignore-workspace", "ignore-workspace-root-check", "include-workspace-root", "lockfile", "lockfile-only", "merge-git-branch-lockfiles", "node-experimental-package-map", "offline", "optimistic-repeat-install", "optional", "parseable", "prefer-frozen-lockfile", "prefer-offline", "production", "recursive", "resolution-only", "runtime", "save", "save-dev", "save-exact", "save-optional", "save-peer", "save-prod", "save-workspace-protocol", "shamefully-hoist", "shared-workspace-lockfile", "side-effects-cache", "side-effects-cache-readonly", "stream", "strict-peer-dependencies", "trust-lockfile", "unsafe-perm", "update-checksums", "use-stderr", "verify-store-integrity", "virtual-store-only", "workspace", "workspace-root", "yes"},
	enums:      map[string][]string{"color": {"always", "auto", "never"}, "link-workspace-packages": {"deep"}},
	shorthands: map[string]string{"?": "--help", "C": "--dir", "D": "--save-dev", "E": "--save-exact", "F": "--filter", "H": "--help", "L": "--latest", "O": "--save-optional", "P": "--save-prod", "S": "--save", "d": "--loglevel=info", "dd": "--loglevel=verbose", "ddd": "--loglevel=silly", "development": "--dev", "f": "--force", "g": "--global", "h": "--help", "i": "--interactive", "l": "--long", "local": "--no-global", "p": "--parseable", "porcelain": "--parseable", "prod": "--production", "q": "--loglevel=warn", "quiet": "--loglevel=warn", "r": "--recursive", "s": "--reporter=silent", "silent": "--reporter=silent", "usage": "--help", "v": "--version", "verbose": "--loglevel=verbose", "w": "--workspace-root", "y": "--yes"},
	aliases:    map[string]string{"adduser": "login", "c": "config", "clean-install": "ci", "dislink": "unlink", "dist-tags": "dist-tag", "find": "search", "home": "docs", "i": "install", "ic": "ci", "info": "view", "install-clean": "ci", "issues": "bugs", "it": "install-test", "la": "ll", "ln": "link", "ls": "list", "m": "recursive", "multi": "recursive", "owners": "owner", "purge": "clean", "rb": "rebuild", "rm": "remove", "rt": "runtime", "run-script": "run", "s": "search", "se": "search", "show": "view", "ss": "set-script", "un": "remove", "uni": "remove", "uninstall": "remove", "up": "update", "upgrade": "update", "v": "view"},
}

// builtinCommands lists every built-in command of each pnpm major by canonical
// name; the nopt aliases and strictAliases resolve the spellings to them.
var builtinCommands = map[int][]string{
	10: {
		"add", "approve-builds", "audit", "bin", "cache", "cat-file", "cat-index", "ci", "completion",
		"completion-server", "config", "create", "dedupe", "deploy", "dlx", "doctor", "env", "exec", "fetch",
		"find-hash", "get", "help", "ignored-builds", "import", "init", "install", "install-test", "licenses",
		"link", "list", "ll", "outdated", "pack", "patch", "patch-commit", "patch-remove", "prune", "publish",
		"rebuild", "recursive", "remove", "restart", "root", "run", "self-update", "server", "set", "setup",
		"store", "unlink", "update", "why",
	},
	11: {
		"access", "add", "approve-builds", "audit", "bin", "bugs", "cache", "cat-file", "cat-index", "change",
		"ci", "clean", "completion", "completion-server", "config", "create", "dedupe", "deploy", "deprecate",
		"dist-tag", "dlx", "doctor", "docs", "edit", "env", "exec", "fetch", "find-hash", "get", "help",
		"ignored-builds", "import", "init", "install", "install-test", "lane", "licenses", "link", "list",
		"ll", "login", "logout", "outdated", "owner", "pack", "pack-app", "patch", "patch-commit",
		"patch-remove", "peers", "ping", "pkg", "prefix", "profile", "prune", "publish", "recursive",
		"rebuild", "remove", "repo", "restart", "root", "run", "runtime", "sbom", "search", "self-update",
		"set", "set-script",
		"setup", "stage", "star", "stars", "store", "team", "token", "undeprecate", "unlink", "unpublish",
		"unstar", "update", "version", "view", "whoami", "why", "with", "xmas",
	},
	12: {
		"access", "add", "approve", "approve-builds", "audit", "bin", "bugs", "cache", "catalog", "cat-file",
		"cat-index", "change", "ci", "clean", "completion", "completion-server", "config", "create", "dedupe",
		"deploy", "deprecate", "dist-tag", "dlx", "doctor", "docs", "edit", "env", "exec", "fetch", "find-hash",
		"fund", "get", "help", "ignored-builds", "import", "init", "install", "install-test", "lane",
		"licenses", "link", "list", "ll", "login", "logout", "outdated", "owner", "pack", "pack-app", "patch",
		"patch-commit", "patch-remove", "peers", "permissions", "ping", "pipeline", "pkg", "prefix", "profile",
		"prune", "publish", "purge", "rb", "rebuild", "recursive", "remove", "repo", "restart", "root", "run",
		"runtime", "sbom", "search", "self-update", "set", "set-script", "setup", "shim", "stage", "star",
		"stars",
		"start", "stop", "store", "tasks", "team", "test", "token", "undeprecate", "unlink", "unpublish",
		"unstar", "update", "version", "view", "whoami", "why", "with", "xmas",
	},
}

// npmPassthrough10 are the pnpm 10 commands pnpm hands to npm, in full, when
// one of them is the raw first argument; pnpm parses anything else itself and
// skips the hand-off when the project pins pnpm 11 or newer.
var npmPassthrough10 = []string{
	"access", "adduser", "bugs", "deprecate", "dist-tag", "docs", "edit", "find", "home", "info", "issues",
	"login", "logout", "owner", "ping", "prefix", "profile", "pkg", "repo", "s", "se", "search", "set-script",
	"show", "star", "stars", "team", "token", "unpublish", "unstar", "v", "version", "view", "whoami", "xmas",
}

// overridableScripts are the built-in commands a same-named package.json
// script replaces, looked up under the name as typed. A `pm` prefix forces
// the built-in on pnpm 11 and 12, and pnpm 11 keeps it under --global.
var overridableScripts = map[int][]string{
	10: nil,
	11: {"clean", "purge", "deploy", "rebuild", "rb", "setup"},
	12: {"clean", "purge", "deploy", "rebuild", "rb", "setup", "tasks"},
}
