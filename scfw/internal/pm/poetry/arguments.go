// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import "strings"

// poetryOwnArguments excludes the executable and arguments of `poetry run`.
// Only Poetry's global directory/project options take values before the command
// or before run's executable. Returned arguments are for discovery only; the
// original command is always forwarded unchanged.
func poetryOwnArguments(command []string) []string {
	run := false
	for i := 0; i < len(command); i++ {
		argument := command[i]
		switch argument {
		case "--":
			return command[:i]
		case "--directory", "-C", "--project", "-P":
			i++
			continue
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		if run {
			return command[:i]
		}
		if argument != "run" {
			return command
		}
		run = true
	}
	return command
}
