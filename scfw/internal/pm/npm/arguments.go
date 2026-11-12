// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import "strings"

type npmOption struct {
	name, value string
}

// Inspect only settings consumed by proxy routing, trust, registries, and
// configuration discovery. Options accept --name value or --name=value; -C and
// -g are the prefix and global shorthands. Abbreviations are not expanded: npm
// deprecates them, and a missed one leaves SCFW without the user's upstream,
// which fails rather than bypassing SCFW.
func parseNpmOptions(args []string) []npmOption {
	var options []npmOption
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			break
		}
		if !strings.HasPrefix(argument, "-") {
			continue
		}
		name, value, supplied := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		name = canonicalNpmOption(argument, name)
		switch {
		case name == "global" || name == "no-global":
			// Like npm's parser: a bare flag takes a following literal true or
			// false as its value, and any other =value still sets the flag.
			enabled := name == "global"
			switch {
			case !enabled:
			case supplied:
				enabled = value != "false"
			case index+1 < len(args) && (args[index+1] == "true" || args[index+1] == "false"):
				index++
				enabled = args[index] == "true"
			}
			name, value = "global", "true"
			if !enabled {
				value = "false"
			}
		case name == "no-strict-ssl":
			if supplied {
				continue
			}
			name, value = "strict-ssl", "false"
		case name == "strict-ssl":
			if !supplied {
				value = "true"
				if index+1 < len(args) && (args[index+1] == "true" || args[index+1] == "false") {
					index++
					value = args[index]
				}
			}
		case isScopedRegistry(name) || isNpmValueOption(name):
			if !supplied {
				index++
				if index >= len(args) {
					return options
				}
				value = args[index]
			}
		default:
			continue
		}
		options = append(options, npmOption{name: name, value: value})
	}
	return options
}

func canonicalNpmOption(argument, name string) string {
	switch argument {
	case "-C":
		return "prefix"
	case "-g":
		return "global"
	}
	if !strings.HasPrefix(argument, "--") {
		return ""
	}
	return name
}

func isNpmValueOption(name string) bool {
	switch name {
	case "https-proxy", "proxy", "noproxy", "cafile", "ca", "registry", "userconfig", "globalconfig", "prefix", "location":
		return true
	}
	return false
}

func isScopedRegistry(name string) bool {
	return strings.HasPrefix(name, "@") && strings.HasSuffix(name, ":registry")
}
