// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build darwin

package proxy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

func newProtectedNPMConfig(contents []byte) (*os.File, func() error, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create npm authentication pipe: %w", err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(contents)
		writeDone <- errors.Join(writeErr, writer.Close())
	}()
	cleanup := func() error {
		readErr := reader.Close()
		writeErr := <-writeDone
		if errors.Is(writeErr, syscall.EPIPE) || errors.Is(writeErr, io.ErrClosedPipe) {
			writeErr = nil
		}
		return errors.Join(readErr, writeErr)
	}
	return reader, cleanup, nil
}
