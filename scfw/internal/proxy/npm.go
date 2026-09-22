// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Streams are connected to the npm child process. Proxy evaluation and report
// events are written to Stdout alongside npm's own output.
type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type synchronizedWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

var unsupportedNPMConfigOptions = map[string]bool{
	"--registry":                        true,
	"--global":                          true,
	"--userconfig":                      true,
	"--globalconfig":                    true,
	"--location":                        true,
	"--prefix":                          true,
	"--proxy":                           true,
	"--https-proxy":                     true,
	"--noproxy":                         true,
	"--strict-ssl":                      true,
	"--ca":                              true,
	"--cafile":                          true,
	"--cert":                            true,
	"--key":                             true,
	"--script-shell":                    true,
	"--omit-lockfile-registry-resolved": true,
	"--replace-registry-host":           true,
	"-g":                                true,
	"-l":                                true,
}

func (writer *synchronizedWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.writer.Write(data)
}

// RunNPM starts an ephemeral registry proxy and runs npm with process-local
// registry overrides that route default and scoped registry traffic through it.
func RunNPM(ctx context.Context, executable string, args []string, streams Streams, options Options) (returnErr error) {
	config, err := LoadNPMConfig(ctx, executable)
	if err != nil {
		return err
	}
	return RunNPMWithConfig(ctx, executable, args, streams, options, config)
}

// RunNPMWithConfig runs npm using configuration discovered by the npm manager
// adapter while retaining npm's protected-descriptor and lifecycle isolation.
func RunNPMWithConfig(ctx context.Context, executable string, args []string, streams Streams, options Options, config NPMConfig) (returnErr error) {
	if err := validateNPMProxyArgs(args); err != nil {
		return err
	}
	if err := validateNPMConfigMode(config); err != nil {
		return err
	}
	if !config.supportsSafeLockfileOmission {
		return errors.New("npm proxy mode requires npm 8 or later to avoid persisting ephemeral proxy URLs in lockfiles")
	}

	stdout := streams.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	synchronizedStdout := &synchronizedWriter{writer: stdout}
	server, err := StartWithOptions(config, options)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		returnErr = errors.Join(returnErr, server.Close(shutdownCtx))
	}()
	authConfig, err := newNPMAuthConfig(config.userConfigFile, server.npmAuthConfigLine())
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, authConfig.Close())
	}()

	childContext, cancelChild := context.WithCancel(ctx)
	defer cancelChild()
	proxyOptions := []string{
		"--registry=" + server.URL(),
		"--userconfig=" + authConfig.path,
		"--omit-lockfile-registry-resolved=true",
		"--replace-registry-host=always",
	}
	scopedURLs := server.scopedRegistryURLs()
	environment := os.Environ()
	overrides := npmProxyOverrides(server.URL(), scopedURLs)
	overriddenNames := make([]string, 0, len(overrides)+4)
	for name := range overrides {
		overriddenNames = append(overriddenNames, name)
	}
	overriddenNames = append(overriddenNames,
		"npm_config_userconfig", "NPM_CONFIG_USERCONFIG",
		"npm_config_script_shell", "NPM_CONFIG_SCRIPT_SHELL",
	)
	scriptShell, err := newNPMScriptShell(config.scriptShell, environment, overriddenNames)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, scriptShell.Close())
	}()
	proxyOptions = append(proxyOptions, "--script-shell="+scriptShell.path)
	scopes := make([]string, 0, len(scopedURLs))
	for scope := range scopedURLs {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		proxyOptions = append(proxyOptions, "--"+scope+":registry="+scopedURLs[scope])
	}
	separator := len(args)
	for index, argument := range args {
		if argument == "--" {
			separator = index
			break
		}
	}
	childArgs := append([]string(nil), args[:separator]...)
	childArgs = append(childArgs, proxyOptions...)
	childArgs = append(childArgs, args[separator:]...)
	child := exec.CommandContext(childContext, executable, childArgs...)
	child.Stdin = streams.Stdin
	child.Stdout = synchronizedStdout
	child.Stderr = streams.Stderr
	child.Env = npmProxyEnvironment(scriptShell.environment, overrides)
	child.ExtraFiles = []*os.File{authConfig.file}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start npm command: %w", err)
	}

	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	select {
	case err := <-childDone:
		if err != nil {
			return fmt.Errorf("run npm command: %w", err)
		}
		return nil
	case err := <-server.Errors():
		cancelChild()
		childErr := <-childDone
		return errors.Join(err, childErr)
	}
}

func validateNPMConfigMode(config NPMConfig) error {
	if config.global || (config.location != "" && config.location != "user") {
		return fmt.Errorf("npm proxy mode does not support effective global or project configuration location (global=%t, location=%q)", config.global, config.location)
	}
	return nil
}

func validateNPMProxyArgs(args []string) error {
	for _, argument := range args {
		if argument == "--" {
			break
		}
		name, _, _ := strings.Cut(strings.ToLower(argument), "=")
		if strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--") && strings.ContainsAny(strings.TrimPrefix(name, "-"), "gl") {
			return fmt.Errorf("npm proxy mode does not support command-line configuration option %q; configure it in npmrc or the environment instead", argument)
		}
		if strings.HasPrefix(name, "-c") && !strings.HasPrefix(name, "--") {
			return fmt.Errorf("npm proxy mode does not support command-line configuration option %q; configure it in npmrc or the environment instead", argument)
		}
		optionNames := []string{name}
		if strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--") && len(name) > 2 {
			optionNames = append(optionNames, "--"+strings.TrimPrefix(name, "-"))
		}
		namedConflict := false
		for _, optionName := range optionNames {
			normalizedName := strings.TrimPrefix(optionName, "--no-")
			if !strings.HasPrefix(normalizedName, "--") && strings.HasPrefix(optionName, "--no-") {
				normalizedName = "--" + normalizedName
			}
			for unsupported := range unsupportedNPMConfigOptions {
				if normalizedName == unsupported || (len(normalizedName) >= 5 && strings.HasPrefix(unsupported, normalizedName)) {
					namedConflict = true
					break
				}
			}
			if namedConflict {
				break
			}
		}
		scopedRegistryConflict := false
		for _, optionName := range optionNames {
			if strings.HasPrefix(optionName, "--@") && strings.HasSuffix(optionName, ":registry") {
				scopedRegistryConflict = true
				break
			}
		}
		conflicts := namedConflict || scopedRegistryConflict ||
			strings.Contains(name, "_authtoken") ||
			strings.HasSuffix(name, ":_auth") ||
			strings.HasSuffix(name, ":username") ||
			strings.HasSuffix(name, ":_password")
		if conflicts {
			return fmt.Errorf("npm proxy mode does not support command-line configuration option %q; configure it in npmrc or the environment instead", argument)
		}
	}
	return nil
}
