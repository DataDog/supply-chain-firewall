// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func newProtectedNPMConfig(contents []byte) (*os.File, func() error, error) {
	descriptor, err := unix.MemfdCreate("scfw-npm-auth", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, nil, fmt.Errorf("create sealed npm authentication descriptor: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "scfw-npm-auth")
	fail := func(operationErr error) (*os.File, func() error, error) {
		return nil, nil, errors.Join(operationErr, file.Close())
	}
	if _, err := file.Write(contents); err != nil {
		return fail(fmt.Errorf("write npm authentication descriptor: %w", err))
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fail(fmt.Errorf("rewind npm authentication descriptor: %w", err))
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return fail(fmt.Errorf("seal npm authentication descriptor: %w", err))
	}
	return file, file.Close, nil
}
