// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build !darwin && !linux

package proxy

import (
	"errors"
	"os"
)

func newProtectedNPMConfig([]byte) (*os.File, func() error, error) {
	return nil, nil, errors.New("npm proxy mode is supported only on macOS and Linux")
}
