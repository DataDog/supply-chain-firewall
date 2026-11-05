// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import "strings"

type pipOption struct {
	name, value string
}

// Inspect only settings consumed by proxy routing, trust, and discovery.
// Consume other value-taking global options so the first target identifies the
// command without a command catalog. Options accept --name value or --name=value;
// the source options also accept -i, -f, -r, and -c.
func parsePipOptions(args []string) ([]pipOption, []string) {
	var options []pipOption
	var targets []string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			targets = append(targets, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			targets = append(targets, argument)
			continue
		}
		name, value, supplied := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		if !strings.HasPrefix(argument, "--") {
			// Leading verbosity flags can be combined with a source option,
			// e.g. -vrfile.txt. Do not inspect values of unknown short options.
			short := strings.TrimLeft(argument[1:], "vq")
			if short == "" {
				continue
			}
			switch short[0] {
			case 'i':
				name = "index-url"
			case 'f':
				name = "find-links"
			case 'r':
				name = "requirement"
			case 'c':
				name = "constraint"
			default:
				continue
			}
			value, supplied = short[1:], len(short) > 1
		}
		switch name {
		case "log", "log-file", "local-log", "keyring-provider", "retries", "timeout", "default-timeout",
			"exists-action", "cache-dir", "use-feature", "use-deprecated", "resume-retries":
			if !supplied {
				index++
			}
			continue
		case "isolated", "no-proxy-env":
			if supplied {
				continue
			}
			value = "true"
		case "proxy", "cert", "client-cert", "trusted-host", "python",
			"index-url", "pypi-url", "extra-index-url", "find-links", "requirement", "constraint", "build-constraint":
			if !supplied {
				index++
				if index >= len(args) {
					return options, targets
				}
				value = args[index]
			}
		default:
			continue
		}
		// Consume references only; pip reads their contents.
		if name == "requirement" || name == "constraint" || name == "build-constraint" {
			continue
		}
		options = append(options, pipOption{name: canonicalPipOption(name), value: value})
	}
	return options, targets
}

func canonicalPipOption(name string) string {
	name = strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(name), "_", "-"), "--")
	if name == "pypi-url" {
		return "index-url"
	}
	return name
}
