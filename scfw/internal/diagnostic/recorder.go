// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package diagnostic writes bounded, sanitized, invocation-local debug journals.
package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	MaxText        = 4096
	maxDocument    = 64 << 10
	maxFile        = 25 << 20
	footerReserve  = 64 << 10
	maxQueuedBytes = 8 << 20
	maxEvents      = 100000
)

type contextKey struct{}

// WithRecorder attaches the journal to existing invocation work, without IDs.
func WithRecorder(ctx context.Context, recorder *Recorder) context.Context {
	return context.WithValue(ctx, contextKey{}, recorder)
}

// FromContext returns nil when recording is disabled.
func FromContext(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(contextKey{}).(*Recorder)
	return r
}

type event struct {
	Timestamp time.Time      `yaml:"timestamp"`
	Type      string         `yaml:"type"`
	Message   string         `yaml:"message"`
	Elapsed   int64          `yaml:"elapsed_ns"`
	Data      map[string]any `yaml:"data,omitempty"`
}

// Recorder serializes sanitized documents through a bounded, nonblocking queue.
// It never changes a package-manager, policy, or transport outcome.
type Recorder struct {
	start                                  time.Time
	file                                   *os.File
	path, partial                          string
	redactor                               *Redactor
	queue                                  chan []byte
	serializers                            chan struct{}
	done                                   chan struct{}
	mu                                     sync.Mutex
	closed                                 bool
	events, dropped, queuedBytes, reserved int
	outcome                                string
	err                                    error
	published                              bool
	abandoned                              atomic.Bool
	closeOnce                              sync.Once
}

// New creates a private sibling temporary file; the destination is never replaced.
// Its parent directory must exist. No credentials are written before sanitization.
func New(path string, manifest map[string]any, redactor *Redactor) (*Recorder, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("diagnostic destination already exists or cannot be checked")
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".partial-*")
	if err != nil {
		return nil, err
	}
	if redactor == nil {
		redactor = NewRedactor(nil, nil)
	}
	r := &Recorder{start: time.Now(), file: file, path: path, partial: file.Name(), redactor: redactor, queue: make(chan []byte, 256), serializers: make(chan struct{}, 32), done: make(chan struct{})}
	go r.write()
	manifest = cloneFields(manifest)
	manifest["schema_version"] = 1
	manifest["format"] = "framed YAML documents; only documents ending with ... are complete"
	manifest["limits"] = map[string]any{"file_bytes": maxFile, "document_bytes": maxDocument, "metadata_text_bytes": MaxText, "events": maxEvents}
	manifest["exclusions"] = []string{"package artifact bodies", "request bodies", "child terminal stdout/stderr", "credentials and private keys", "environment dumps"}
	r.Record("manifest", "Supply Chain Firewall diagnostic capture", manifest)
	return r, nil
}

func cloneFields(fields map[string]any) map[string]any {
	result := make(map[string]any, len(fields)+4)
	for key, value := range fields {
		result[key] = value
	}
	return result
}

// Record drops data rather than waiting for file I/O or unbounded queue space.
func (r *Recorder) Record(kind, message string, fields map[string]any) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed || r.err != nil || r.events >= maxEvents {
		r.dropped++
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	select {
	case r.serializers <- struct{}{}:
		defer func() { <-r.serializers }()
	default:
		r.mu.Lock()
		r.dropped++
		r.mu.Unlock()
		return
	}
	frame, err := r.document(kind, message, fields)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || len(frame) > maxDocument || r.closed || r.err != nil || r.events >= maxEvents || r.reserved+len(frame) > maxFile-footerReserve || r.queuedBytes+len(frame) > maxQueuedBytes {
		r.dropped++
		return
	}
	select {
	case r.queue <- frame:
		r.events++
		r.reserved += len(frame)
		r.queuedBytes += len(frame)
	default:
		r.dropped++
	}
}

func (r *Recorder) document(kind, message string, fields map[string]any) ([]byte, error) {
	data, _ := r.redactor.Value(fields).(map[string]any)
	cleanMessage := r.redactor.Text(message)
	if len(cleanMessage) > MaxText {
		cleanMessage = "[omitted oversized log message]"
	}
	if len(kind) > 128 {
		kind = "omitted"
	}
	document := event{Timestamp: time.Now().UTC(), Type: r.redactor.Text(kind), Message: cleanMessage, Elapsed: int64(time.Since(r.start)), Data: data}
	encoded, err := yaml.Marshal(document)
	if len(encoded) > maxDocument-8 {
		document.Data = map[string]any{"omitted": "fields exceed serialized document limit"}
		if kind == "manifest" {
			document.Data["schema_version"] = 1
		}
		encoded, err = yaml.Marshal(document)
	}
	if err != nil {
		return nil, err
	}
	return append(append([]byte("---\n"), encoded...), []byte("...\n")...), nil
}

// Path is the requested final location, including the full filesystem path.
func (r *Recorder) Path() string { return r.path }

// Redactor is immutable and safe for concurrent observation callbacks.
func (r *Recorder) Redactor() *Redactor { return r.redactor }

func (r *Recorder) write() {
	defer close(r.done)
	var offset int64
	var failure error
	for frame := range r.queue {
		if failure == nil {
			var n int
			n, failure = r.file.Write(frame)
			if failure == nil && n != len(frame) {
				failure = errors.New("short diagnostic write")
			}
			if failure == nil {
				offset += int64(n)
			} else {
				_ = r.file.Truncate(offset)
			}
		}
		r.mu.Lock()
		r.queuedBytes -= len(frame)
		if failure != nil {
			r.err = failure
		}
		r.mu.Unlock()
	}
	r.mu.Lock()
	fields := map[string]any{"outcome": r.outcome, "events": r.events, "dropped_events": r.dropped, "complete": failure == nil && r.dropped == 0}
	r.mu.Unlock()
	if failure == nil {
		frame, err := r.document("summary", "Diagnostic capture finished", fields)
		if err == nil {
			_, err = r.file.Write(frame)
		}
		if err != nil {
			failure = err
			_ = r.file.Truncate(offset)
		}
	}
	if err := r.file.Sync(); failure == nil {
		failure = err
	}
	if err := r.file.Close(); failure == nil {
		failure = err
	}
	// A failed write can still leave a useful complete-document prefix.
	if !r.abandoned.Load() {
		if err := os.Link(r.partial, r.path); err == nil {
			r.mu.Lock()
			r.published = true
			r.mu.Unlock()
			_ = os.Remove(r.partial)
		} else if failure == nil {
			failure = err
		}
	}
	r.mu.Lock()
	r.err = failure
	r.mu.Unlock()
}

// Close publishes a readable journal or reports where its partial can be recovered.
// A bounded wait cannot cancel a filesystem call already in progress.
func (r *Recorder) Close(outcome string) (string, error) {
	if r == nil {
		return "", nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.outcome = outcome
		close(r.queue)
		r.mu.Unlock()
	})
	if r.abandoned.Load() {
		return r.partial, errors.New("diagnostic finalization timed out")
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.published {
			return r.path, r.err
		}
		return r.partial, r.err
	case <-timer.C:
		r.abandoned.Store(true)
		return r.partial, fmt.Errorf("diagnostic finalization timed out")
	}
}
