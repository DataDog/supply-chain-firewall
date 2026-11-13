// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// CommandSpec configures a child process for one proxy invocation. Args excludes
// the executable. EnvOverrides applies only to the child; an empty value sets
// the variable to empty, which differs from removing it.
type CommandSpec struct {
	Executable   string
	Args         []string
	EnvOverrides map[string]string
	// EnvRemovals unsets child-only variables whose presence has meaning even
	// when their value is empty. Overrides are applied after these removals.
	EnvRemovals []string
}

// CommandConfigurer is implemented by adapters which configure commands to use
// the supplied proxy and CA. Keeping this contract here allows the proxy to run
// an adapter's command without importing any package-manager package.
type CommandConfigurer interface {
	ProxyCommand(ctx context.Context, command []string, config ClientConfig) (CommandSpec, error)
}

// Run starts an invocation-scoped proxy, asks configurer for a command, and runs
// it with inherited streams and child-only environment overrides. The proxy and
// its CA are cleaned up on every exit path. ctx controls the whole invocation;
// SIGINT and SIGTERM also cancel execution. Callers can share their parent
// cancellation context with policy evaluation.
// commandErr contains process launch, exit, or cancellation failures;
// setupErr contains proxy startup or adapter-configuration failures.
func Run(ctx context.Context, options Options, command []string, configurer CommandConfigurer) (commandErr, setupErr error) {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := Start(ctx, options)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := server.Close(); err != nil {
			slog.Warn("failed to stop command proxy cleanly", "error", err)
		}
	}()
	config := server.ClientConfig()
	if len(options.AdditionalClients) > 0 {
		config.AdditionalClients = make(map[string]ClientConfig, len(options.AdditionalClients))
		for name, clientOptions := range options.AdditionalClients {
			clientOptions.ClientIdentity = "client:" + name
			clientOptions.RequestHooks = append(slices.Clone(options.RequestHooks), clientOptions.RequestHooks...)
			client, err := Start(ctx, clientOptions)
			if err != nil {
				return nil, err
			}
			defer func() {
				if err := client.Close(); err != nil {
					slog.Warn("failed to stop command proxy cleanly", "error", err)
				}
			}()
			config.AdditionalClients[name] = client.ClientConfig()
		}
	}
	spec, err := configurer.ProxyCommand(ctx, command, config)
	if err != nil {
		return nil, fmt.Errorf("configure proxied command: %w", err)
	}
	if spec.Executable == "" {
		return nil, errors.New("proxied command executable is empty")
	}

	child := exec.CommandContext(ctx, spec.Executable, spec.Args...)
	environment := os.Environ()
	if len(spec.EnvRemovals) > 0 {
		filtered := make([]string, 0, len(environment))
		for _, entry := range environment {
			key, _, _ := strings.Cut(entry, "=")
			if !slices.Contains(spec.EnvRemovals, key) {
				filtered = append(filtered, entry)
			}
		}
		environment = filtered
	}
	child.Env = applyEnvironmentOverrides(environment, spec.EnvOverrides)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Terminal jobs retain the shell's foreground group for Ctrl-Z and fg.
	// Other runs use an isolated group to also cancel build/VCS descendants.
	separateGroup := !term.IsTerminal(int(os.Stdin.Fd()))
	if separateGroup {
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	child.Cancel = func() error {
		received := os.Signal(os.Interrupt)
		select {
		case received = <-signals:
		case <-time.After(20 * time.Millisecond):
		}
		if separateGroup {
			return syscall.Kill(-child.Process.Pid, received.(syscall.Signal))
		}
		// A signal sent to SCFW itself must reach its own terminal job too.
		// Cancellation is already in progress, so this notification cannot recurse.
		if group := syscall.Getpgrp(); group == os.Getpid() {
			return syscall.Kill(-group, received.(syscall.Signal))
		}
		return child.Process.Signal(received)
	}
	child.WaitDelay = 5 * time.Second
	slog.Debug("running command through proxy")
	err = child.Run()
	if separateGroup && child.Process != nil {
		_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	}
	return err, nil
}

func applyEnvironmentOverrides(environment []string, overrides map[string]string) []string {
	result := make([]string, 0, len(environment)+len(overrides))
	for _, item := range environment {
		key, _, _ := strings.Cut(item, "=")
		if _, overridden := overrides[key]; !overridden {
			result = append(result, item)
		}
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		result = append(result, key+"="+overrides[key])
	}
	return result
}
