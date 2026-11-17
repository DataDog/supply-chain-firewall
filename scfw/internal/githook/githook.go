// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package githook provides invocation-scoped Git hooks that let SCFW decide on
// checkouts before the client that requested them uses the files.
package githook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// Checkout is a working tree Git has just checked out.
type Checkout struct {
	Dir, Origin, SHA string
}

// Decide rules on a checkout. A non-nil error blocks it, and its text is shown
// to the user.
type Decide func(ctx context.Context, checkout Checkout) error

// core.hooksPath replaces every hook location, so each standard hook forwards
// to the one Git would otherwise have run (githooks(5)).
var hookNames = []string{
	"applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
	"prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
	"pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
	"reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
	"post-index-change",
}

// maxSocketPath is the size of sun_path on macOS, the shorter of the release targets.
const maxSocketPath = 104

// Hooks serves checkout decisions for one invocation until it is closed.
type Hooks struct {
	dir      string
	listener net.Listener
	cancel   context.CancelFunc
	group    sync.WaitGroup
}

type request struct {
	Dir    string `json:"dir"`
	Origin string `json:"origin"`
	SHA    string `json:"sha"`
}

type response struct {
	Blocked bool   `json:"blocked"`
	Message string `json:"message"`
}

// Start writes a private hooks directory whose scripts run executable's
// git-hook command, and serves their checkout requests with decide.
func Start(ctx context.Context, executable string, decide Decide) (*Hooks, error) {
	dir, err := os.MkdirTemp("", "scfw-git-hooks-")
	if err != nil {
		return nil, errors.New("could not create git hooks directory")
	}
	hooks, err := start(ctx, dir, executable, decide)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return hooks, nil
}

func start(ctx context.Context, dir, executable string, decide Decide) (*Hooks, error) {
	socket := filepath.Join(dir, "s")
	if len(socket) >= maxSocketPath {
		return nil, fmt.Errorf("git hook socket path %q is too long", socket)
	}
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.Mkdir(hooksDir, 0o700); err != nil {
		return nil, errors.New("could not create git hooks directory")
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %s git-hook %s \"$(basename \"$0\")\" \"$@\"\n", shellQuoted(executable), shellQuoted(socket))
	for _, name := range hookNames {
		if err := os.WriteFile(filepath.Join(hooksDir, name), []byte(script), 0o700); err != nil {
			return nil, errors.New("could not write git hook")
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen for git hooks: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	hooks := &Hooks{dir: dir, listener: listener, cancel: cancel}
	hooks.group.Go(func() { hooks.serve(ctx, decide) })
	return hooks, nil
}

func (h *Hooks) serve(ctx context.Context, decide Decide) {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.group.Go(func() {
			defer func() { _ = conn.Close() }()
			var checkout request
			if json.NewDecoder(conn).Decode(&checkout) != nil {
				return
			}
			var answer response
			if err := decide(ctx, Checkout(checkout)); err != nil {
				answer = response{Blocked: true, Message: err.Error()}
			}
			_ = json.NewEncoder(conn).Encode(answer)
		})
	}
}

// Apply makes the command's Git use these hooks. The entry is appended after
// existing command-scope configuration, so it takes precedence over it.
func (h *Hooks) Apply(spec *proxy.CommandSpec) {
	if spec.EnvOverrides == nil {
		spec.EnvOverrides = map[string]string{}
	}
	count, found := spec.EnvOverrides["GIT_CONFIG_COUNT"]
	if !found {
		count = os.Getenv("GIT_CONFIG_COUNT")
	}
	index, err := strconv.Atoi(count)
	if err != nil || index < 0 {
		index = 0
	}
	spec.EnvOverrides["GIT_CONFIG_KEY_"+strconv.Itoa(index)] = "core.hooksPath"
	spec.EnvOverrides["GIT_CONFIG_VALUE_"+strconv.Itoa(index)] = filepath.Join(h.dir, "hooks")
	spec.EnvOverrides["GIT_CONFIG_COUNT"] = strconv.Itoa(index + 1)
}

// Close stops serving, ends pending decisions, and removes the hooks.
func (h *Hooks) Close() error {
	h.cancel()
	err := h.listener.Close()
	h.group.Wait()
	if removeErr := os.RemoveAll(h.dir); err == nil {
		err = removeErr
	}
	return err
}

func shellQuoted(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
