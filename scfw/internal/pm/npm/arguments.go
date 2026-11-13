// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"slices"
	"strings"
)

// npmCommandIndex consumes value-taking global options before identifying the
// subcommand. Option values named "install" must not select install verification.
func npmCommandIndex(args []string) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return i + 1
			}
			return -1
		}
		if !strings.HasPrefix(a, "-") {
			return i
		}
		key, boolean, e := npmOption(a)
		if e != nil {
			return -2
		}
		if strings.Contains(a, "=") {
			continue
		}
		if !boolean {
			if i+1 >= len(args) {
				return -2
			}
			i++
		} else if i+1 < len(args) && npmBooleanValue(key, args[i+1]) {
			i++
		}
	}
	return -1
}
func npmInstallCommandSupported(command []string) bool {
	idx := npmCommandIndex(command)
	if idx == -2 {
		return true
	}
	if idx < 0 {
		return false
	}
	if !slices.Contains(npmInstallCommandAliases, command[idx]) {
		return false
	}
	settings := npmCLIConfig(command)
	for _, key := range []string{"dry-run", "help", "version"} {
		if v := settings[key]; v != "" && v != "false" {
			return false
		}
	}

	return true
}
