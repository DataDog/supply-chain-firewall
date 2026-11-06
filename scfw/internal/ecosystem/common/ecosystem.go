// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package common defines shared ecosystem domain types without depending on
// registry implementations or package-manager adapters.
package common

// Ecosystem identifies a package registry ecosystem.
type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PYPI Ecosystem = "PyPI"
)
