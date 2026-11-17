// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package diagnostic

import (
	"context"
	"log/slog"
	"strings"
)

type logHandler struct {
	console  slog.Handler
	recorder *Recorder
	attrs    []slog.Attr
	group    string
}

// LogHandler captures SCFW records separately from unchanged console filtering.
func LogHandler(console slog.Handler, recorder *Recorder) slog.Handler {
	return &logHandler{console: console, recorder: recorder}
}

func (h *logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelDebug || h.console.Enabled(ctx, level)
}
func (h *logHandler) Handle(ctx context.Context, record slog.Record) error {
	var err error
	if h.console.Enabled(ctx, record.Level) {
		err = h.console.Handle(ctx, record)
	}
	fields := map[string]any{"level": record.Level.String()}
	add := func(attr slog.Attr) {
		key := h.group + attr.Key
		if strings.Contains(strings.ToLower(key), "body") {
			fields[key] = "[omitted raw log body]"
			return
		}
		// Value.Any does not resolve LogValuer. The redactor rejects opaque types.
		fields[key] = attr.Value.Any()
	}
	for _, attr := range h.attrs {
		add(attr)
	}
	record.Attrs(func(attr slog.Attr) bool { add(attr); return len(fields) < 128 })
	h.recorder.Record("log", record.Message, fields)
	return err
}
func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := *h
	copy.console = h.console.WithAttrs(attrs)
	copy.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &copy
}
func (h *logHandler) WithGroup(name string) slog.Handler {
	copy := *h
	copy.console = h.console.WithGroup(name)
	if name != "" {
		copy.group += name + "."
	}
	return &copy
}
