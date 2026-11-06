// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sync"
)

// InspectReader provides bounded, temporary-file inspection for a decoded or
// independently fetched response. It does not close the supplied reader. The
// read-only view is valid only during handle; the file is always removed.
func InspectReader(ctx context.Context, reader io.Reader, maxBytes int64, handle func(*io.SectionReader) error) error {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 || handle == nil {
		return errors.New("invalid proxy file inspection")
	}
	file, err := os.CreateTemp("", "scfw-inspect-*")
	if err != nil {
		return errors.New("could not create proxy inspection file")
	}
	cleanup := sync.OnceFunc(func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	})
	stopCleanup := context.AfterFunc(ctx, cleanup)
	defer func() { stopCleanup(); cleanup() }()
	written, err := io.Copy(file, io.LimitReader(contextReader{ctx, reader}, maxBytes+1))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return errors.New("decoded response exceeds inspection limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return handle(io.NewSectionReader(file, 0, written))
}

func inspectResponseFile(ctx context.Context, request Request, response *http.Response, hooks []*ResponseBodyHook, directory string, length, limit int64) error {
	file, err := os.CreateTemp(directory, "response-*")
	if err != nil {
		return errors.New("could not create proxy response file")
	}
	cleanup := sync.OnceFunc(func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	})
	stopCleanup := context.AfterFunc(ctx, cleanup)
	retained := false
	defer func() {
		if !retained {
			stopCleanup()
			cleanup()
		}
	}()
	readLimit := limit + 1
	if length >= 0 {
		readLimit = length
	}
	written, err := io.Copy(file, io.LimitReader(contextReader{ctx, response.Body}, readLimit))
	if err != nil {
		return err
	}
	if written > limit {
		slog.Warn("proxy response exceeds inspection limit", "url", redactURL(&request.URL), "limit_bytes", limit)
		return errors.New("upstream response exceeds inspection limit")
	}
	if length >= 0 && written != length {
		return io.ErrUnexpectedEOF
	}
	for _, hook := range hooks {
		if err := ctx.Err(); err != nil {
			return err
		}
		reader := io.NewSectionReader(file, 0, written)
		if hook.HandleFile != nil {
			if err := hook.HandleFile(ctx, responseSnapshot(request, response, nil), reader); err != nil {
				return err
			}
		} else {
			body, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if err := hook.Handle(ctx, responseSnapshot(request, response, body)); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	upstream := response.Body
	response.Body = &bufferedResponseBody{
		Reader: io.MultiReader(io.NewSectionReader(file, 0, written), upstream),
		Closer: responseFileCloser{upstream: upstream, cleanup: func() {
			stopCleanup()
			cleanup()
		}},
	}
	retained = true
	return nil
}

type responseFileCloser struct {
	upstream io.Closer
	cleanup  func()
}

func (closer responseFileCloser) Close() error {
	defer closer.cleanup()
	return closer.upstream.Close()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
