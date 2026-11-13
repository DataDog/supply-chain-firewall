// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"errors"
	"strings"
)

// npmOptionBooleans is the public npm/@npmcli/config option catalog from
// npm v10.9.9. Unknown/ambiguous options fail closed before preflight execution.
var npmOptionBooleans = map[string]bool{
	"_auth":                           false,
	"access":                          false,
	"all":                             true,
	"allow-same-version":              true,
	"also":                            false,
	"audit":                           true,
	"audit-level":                     false,
	"auth-type":                       false,
	"before":                          false,
	"bin-links":                       true,
	"browser":                         false,
	"ca":                              false,
	"cache":                           false,
	"cache-max":                       false,
	"cache-min":                       false,
	"cafile":                          false,
	"call":                            false,
	"cert":                            false,
	"cidr":                            false,
	"color":                           true,
	"commit-hooks":                    true,
	"cpu":                             false,
	"depth":                           false,
	"description":                     true,
	"dev":                             true,
	"diff":                            false,
	"diff-ignore-all-space":           true,
	"diff-name-only":                  true,
	"diff-no-prefix":                  true,
	"diff-dst-prefix":                 false,
	"diff-src-prefix":                 false,
	"diff-text":                       true,
	"diff-unified":                    false,
	"dry-run":                         true,
	"editor":                          false,
	"engine-strict":                   true,
	"expect-result-count":             false,
	"expect-results":                  true,
	"fetch-retries":                   false,
	"fetch-retry-factor":              false,
	"fetch-retry-maxtimeout":          false,
	"fetch-retry-mintimeout":          false,
	"fetch-timeout":                   false,
	"force":                           true,
	"foreground-scripts":              true,
	"format-package-lock":             true,
	"fund":                            true,
	"git":                             false,
	"git-tag-version":                 true,
	"global":                          true,
	"globalconfig":                    false,
	"global-style":                    true,
	"heading":                         false,
	"https-proxy":                     false,
	"if-present":                      true,
	"ignore-scripts":                  true,
	"include":                         false,
	"include-staged":                  true,
	"include-workspace-root":          true,
	"init-author-email":               false,
	"init-author-name":                false,
	"init-author-url":                 false,
	"init-license":                    false,
	"init-module":                     false,
	"init-version":                    false,
	"init.author.email":               false,
	"init.author.name":                false,
	"init.author.url":                 false,
	"init.license":                    false,
	"init.module":                     false,
	"init.version":                    false,
	"install-links":                   true,
	"install-strategy":                false,
	"json":                            true,
	"key":                             false,
	"legacy-bundling":                 true,
	"legacy-peer-deps":                true,
	"libc":                            false,
	"link":                            true,
	"local-address":                   false,
	"location":                        false,
	"lockfile-version":                false,
	"loglevel":                        false,
	"logs-dir":                        false,
	"logs-max":                        false,
	"long":                            true,
	"maxsockets":                      false,
	"message":                         false,
	"node-options":                    false,
	"noproxy":                         false,
	"offline":                         true,
	"omit":                            false,
	"omit-lockfile-registry-resolved": true,
	"only":                            false,
	"optional":                        true,
	"os":                              false,
	"otp":                             false,
	"package":                         false,
	"package-lock":                    true,
	"package-lock-only":               true,
	"pack-destination":                false,
	"parseable":                       true,
	"prefer-dedupe":                   true,
	"prefer-offline":                  true,
	"prefer-online":                   true,
	"prefix":                          false,
	"preid":                           false,
	"production":                      true,
	"progress":                        true,
	"provenance":                      true,
	"provenance-file":                 false,
	"proxy":                           false,
	"read-only":                       true,
	"rebuild-bundle":                  true,
	"registry":                        false,
	"replace-registry-host":           false,
	"save":                            true,
	"save-bundle":                     true,
	"save-dev":                        true,
	"save-exact":                      true,
	"save-optional":                   true,
	"save-peer":                       true,
	"save-prefix":                     false,
	"save-prod":                       true,
	"sbom-format":                     false,
	"sbom-type":                       false,
	"scope":                           false,
	"script-shell":                    false,
	"searchexclude":                   false,
	"searchlimit":                     false,
	"searchopts":                      false,
	"searchstaleness":                 false,
	"shell":                           false,
	"shrinkwrap":                      true,
	"sign-git-commit":                 true,
	"sign-git-tag":                    true,
	"strict-peer-deps":                true,
	"strict-ssl":                      true,
	"tag":                             false,
	"tag-version-prefix":              false,
	"timing":                          true,
	"umask":                           false,
	"unicode":                         true,
	"update-notifier":                 true,
	"usage":                           true,
	"user-agent":                      false,
	"userconfig":                      false,
	"version":                         true,
	"versions":                        true,
	"viewer":                          false,
	"which":                           false,
	"workspace":                       false,
	"workspaces":                      true,
	"workspaces-update":               true,
	"yes":                             true,
}

func npmOption(argument string) (key string, boolean bool, err error) {
	argument, _, _ = strings.Cut(argument, "=")
	switch argument {
	case "-f":
		return "force", true, nil
	case "-y":
		return "yes", true, nil
	case "-ws":
		return "workspaces", true, nil
	case "-iwr":
		return "include-workspace-root", true, nil
	case "-L":
		return "location", false, nil
	case "-P":
		return "save-prod", true, nil
	case "-B":
		return "save-bundle", true, nil
	case "-l":
		return "long", true, nil
	case "-p":
		return "parseable", true, nil
	case "-a":
		return "all", true, nil
	case "-g":
		return "global", true, nil
	case "-C":
		return "prefix", false, nil
	case "-w":
		return "workspace", false, nil
	case "-h":
		return "help", true, nil
	case "-v":
		return "version", true, nil
	case "-s", "-q":
		return "loglevel", true, nil
	case "-D":
		return "save-dev", true, nil
	case "-S":
		return "save-prod", true, nil
	case "-E":
		return "save-exact", true, nil
	case "-O":
		return "save-optional", true, nil
	}
	if !strings.HasPrefix(argument, "--") {
		return "", false, errors.New("unsupported npm short option")
	}
	name := strings.TrimPrefix(argument, "--")
	negated := strings.HasPrefix(name, "no-")
	name = strings.TrimPrefix(name, "no-")
	if strings.Contains(name, ":") {
		return name, negated, nil
	}
	if boolean, ok := npmOptionBooleans[name]; ok {
		return name, boolean || negated, nil
	}
	if name == "help" || name == "version" {
		return name, true, nil
	}
	match := ""
	for candidate := range npmOptionBooleans {
		if strings.HasPrefix(candidate, name) {
			if match != "" {
				return "", false, errors.New("ambiguous npm option")
			}
			match = candidate
		}
	}
	if match == "" {
		return "", false, errors.New("unsupported npm option")
	}
	return match, npmOptionBooleans[match] || negated, nil
}
func npmCommandError(command []string) error {
	if npmCommandIndex(command) == -2 {
		return errors.New("cannot safely identify npm command options")
	}
	return nil
}

func npmBooleanValue(key, value string) bool {
	if value == "null" {
		switch key {
		case "production", "optional", "workspaces", "expect-results", "yes":
			return true
		}
	}
	return value == "true" || value == "false" || key == "color" && value == "always"
}
