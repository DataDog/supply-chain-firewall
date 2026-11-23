//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHarnessCaseTempSocket(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			output := filepath.Join(t.TempDir(), strings.Repeat("long-evidence-", 12))
			var shortRoot, retained string
			failure := errors.New("scenario failed after opening socket")
			spec := plannedCase{ID: "socket", scenario: scenario{Timeout: time.Minute, Run: func(r *caseRun) error {
				shortRoot = filepath.Dir(filepath.Dir(r.Env["TMPDIR"]))
				dir, err := os.MkdirTemp(r.Env["TMPDIR"], "scfw-git-hooks-")
				if err != nil {
					return err
				}
				listener, err := net.Listen("unix", filepath.Join(dir, "s"))
				if err != nil {
					return err
				}
				if err := listener.Close(); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(dir, "retained-evidence"), []byte("retained"), 0600); err != nil {
					return err
				}
				retained = filepath.Join(r.Root, "tmp", filepath.Base(dir), "retained-evidence")
				// WalkDir must follow intermediate aliases and still see temp files.
				seen := false
				if err := filepath.WalkDir(r.Env["TMPDIR"], func(path string, entry os.DirEntry, err error) error {
					seen = seen || entry != nil && entry.Name() == "retained-evidence"
					return err
				}); err != nil || !seen {
					return errors.New("temporary files are hidden from cleanup inspection")
				}
				if fail {
					return failure
				}
				return nil
			}}}
			err := executeCase(context.Background(), inputs{Output: output}, spec, discovery{}, &result{})
			if (!fail && err != nil) || (fail && !errors.Is(err, failure)) {
				t.Fatalf("scenario returned %v", err)
			}
			if _, err := os.Lstat(shortRoot); !os.IsNotExist(err) {
				t.Fatalf("temporary alias survived scenario: %v", err)
			}
			data, err := os.ReadFile(retained)
			if err != nil || string(data) != "retained" {
				t.Fatalf("scenario evidence was removed with alias: %v", err)
			}
		})
	}
}
