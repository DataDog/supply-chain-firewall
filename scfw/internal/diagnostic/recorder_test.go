// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package diagnostic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func readJournal(t *testing.T, path string) ([]byte, []map[string]any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var records []map[string]any
	for {
		var record map[string]any
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return body, records
}

func TestReadableYAMLAndRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.yaml")
	r, err := New(path, map[string]any{"working_directory": "/home/alice/private-project", "command": []string{"pip", "install"}}, NewRedactor([]string{"API_TOKEN=environment-canary"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published before finalization")
	}
	r.Record("http.response", "Received registry metadata", map[string]any{"body": map[string]any{"text": "metadata line one\nmetadata line two\n"}, "url": "https://user:userinfo-canary@registry.test/pkg?token=query-canary#fragment-canary", "nested": map[string]any{"token": "nested-canary"}, "message": "environment-canary"})
	result, err := r.Close("completed")
	if err != nil || result != path {
		t.Fatalf("close: %s %v", result, err)
	}
	body, records := readJournal(t, path)
	if len(records) != 3 || records[0]["type"] != "manifest" || records[2]["type"] != "summary" {
		t.Fatalf("records: %v", records)
	}
	for _, secret := range []string{"environment-canary", "userinfo-canary", "query-canary", "fragment-canary", "nested-canary"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("leaked %s", secret)
		}
	}
	for _, expected := range []string{"/home/alice/private-project", "Received registry metadata", "text: |", "metadata line one", "schema_version: 1", "...\n---\n"} {
		if !bytes.Contains(body, []byte(expected)) {
			t.Errorf("missing human-readable context %q", expected)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temporary file not cleaned: %v", entries)
	}
	if _, err := r.Close("again"); err != nil {
		t.Fatal(err)
	}
}

func TestWriterNeverOverwrites(t *testing.T) {
	for _, existsFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "existing", false: "publication race"}[existsFirst], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run.yaml")
			if existsFirst {
				if err := os.WriteFile(path, []byte("existing content"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := New(path, nil, nil)
			if existsFirst {
				if err == nil {
					t.Fatal("accepted existing destination")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("existing content"), 0o600); err != nil {
				t.Fatal(err)
			}
			partial, err := r.Close("completed")
			if err == nil || partial == path {
				t.Fatal("did not preserve collision partial")
			}
			body, _ := os.ReadFile(path)
			if string(body) != "existing content" {
				t.Fatal("overwrote destination")
			}
			_, records := readJournal(t, partial)
			if len(records) < 1 {
				t.Fatal("partial is not readable")
			}
		})
	}
}

func TestWriterFailureRetainsCompletedPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.yaml")
	r, err := New(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		info, err := os.Stat(r.partial)
		if err == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manifest not written")
		}
		time.Sleep(time.Millisecond)
	}
	// A closed file injects a real write/flush/close failure without exhausting
	// the developer's disk. The command-facing code never receives this error.
	_ = r.file.Close()
	r.Record("test", "After simulated disk failure", nil)
	result, err := r.Close("failed")
	if err == nil {
		t.Fatal("missing capture error")
	}
	_, records := readJournal(t, result)
	if len(records) < 1 || records[0]["type"] != "manifest" {
		t.Fatal("lost readable prefix")
	}
}

type opaqueValue struct{ called *bool }

func (v opaqueValue) String() string            { *v.called = true; panic("must not format") }
func (v opaqueValue) Error() string             { return v.String() }
func (v opaqueValue) MarshalYAML() (any, error) { return v.String(), nil }

func TestRecorderBoundsAndOpaqueValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.yaml")
	r, err := New(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	r.Record("test", "Oversized and opaque data", map[string]any{"opaque": opaqueValue{&called}, "oversized": strings.Repeat("sensitive-canary", 10000)})
	var group sync.WaitGroup
	for i := 0; i < 40; i++ {
		group.Go(func() {
			for j := 0; j < 40; j++ {
				r.Record("concurrent", "Concurrent diagnostic event", map[string]any{"text": strings.Repeat("x", 2048)})
			}
		})
	}
	group.Wait()
	if _, err := r.Close("completed"); err != nil {
		t.Fatal(err)
	}
	body, records := readJournal(t, path)
	if called || bytes.Contains(body, []byte("sensitive-canary")) {
		t.Fatal("formatted unsafe data")
	}
	if len(body) > maxFile {
		t.Fatal("file budget exceeded")
	}
	for _, frame := range bytes.Split(body, []byte("...\n")) {
		if len(frame) > maxDocument {
			t.Fatal("document budget exceeded")
		}
	}
	if records[len(records)-1]["type"] != "summary" {
		t.Fatal("no completion summary")
	}
}

func TestLogCapturePreservesConsoleThreshold(t *testing.T) {
	var console bytes.Buffer
	r, err := New(filepath.Join(t.TempDir(), "run.yaml"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(LogHandler(slog.NewTextHandler(&console, &slog.HandlerOptions{Level: slog.LevelWarn}), r))
	logger.Debug("Debug context", "body", "raw-body-canary", "token", "log-token-canary")
	logger.Warn("Visible warning")
	if _, err := r.Close("completed"); err != nil {
		t.Fatal(err)
	}
	body, _ := readJournal(t, r.Path())
	if strings.Contains(console.String(), "Debug context") || !strings.Contains(console.String(), "Visible warning") {
		t.Fatal("changed console filtering")
	}
	if !bytes.Contains(body, []byte("Debug context")) || bytes.Contains(body, []byte("raw-body-canary")) || bytes.Contains(body, []byte("log-token-canary")) {
		t.Fatal("unsafe or absent capture logs")
	}
	if FromContext(context.Background()) != nil || FromContext(WithRecorder(context.Background(), r)) != r {
		t.Fatal("incorrect invocation scoping")
	}
}

func TestRedactorArgumentsPreservesPaths(t *testing.T) {
	r := NewRedactor(nil, nil)
	args := r.Arguments([]string{"pip", "install", "--password", "argument-canary", "/home/alice/private-project/tokenizer", "--token=assigned-canary", "https://user:url-canary@registry.test/pkg?key=query-canary"})
	joined := strings.Join(args, " ")
	for _, secret := range []string{"argument-canary", "assigned-canary", "url-canary", "query-canary"} {
		if strings.Contains(joined, secret) {
			t.Errorf("leaked %s", secret)
		}
	}
	if !strings.Contains(joined, "/home/alice/private-project/tokenizer") {
		t.Fatal("anonymized harmless filesystem path")
	}
}

func TestRedactorRelativeURLsAndOpaqueErrors(t *testing.T) {
	r := NewRedactor(nil, nil)
	called := false
	fields := r.Value(map[string]any{"location": "/objects/pkg?signature=relative-canary#fragment-canary", "url": "https://registry.test/auth/path-canary/pkg", "working_directory": "/home/alice/private-project", "error": opaqueValue{&called}})
	body, err := yaml.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"relative-canary", "fragment-canary", "path-canary"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("leaked %s", secret)
		}
	}
	if called || !bytes.Contains(body, []byte("/home/alice/private-project")) {
		t.Fatal("formatted an opaque error or anonymized filesystem context")
	}
}
