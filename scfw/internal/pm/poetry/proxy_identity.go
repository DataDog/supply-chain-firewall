// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func poetryCertificatePrefix(name string) string {
	return "POETRY_CERTIFICATES_" + poetryEnvironmentName(name) + "_"
}

func poetryEnvironmentName(name string) string {
	// Config uses Python's full Unicode uppercasing, including expansions.
	return cases.Upper(language.Und).String(strings.ReplaceAll(name, "-", "_"))
}
