// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	registryproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	bunproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/bun"
	npmproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/npm"
	pipproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/pip"
	pnpmproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/pnpm"
	poetryproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/poetry"
	uvproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/uv"
	yarnproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/yarn"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy -- <package-manager> <args...>",
	Short: "Run a package manager through an experimental local registry proxy.",
	Args:  validateProxyArgs,
	RunE:  runProxy,
}

func init() {
	proxyCmd.Flags().Int("http-status", 0, "Return this HTTP status for intercepted requests without contacting the registry")
}

func validateProxyArgs(cmd *cobra.Command, args []string) error {
	httpStatus, err := cmd.Flags().GetInt("http-status")
	if err != nil {
		return fmt.Errorf("scfw proxy: read --http-status: %w", err)
	}
	if cmd.Flags().Changed("http-status") && (httpStatus < 200 || httpStatus > 599) {
		return fmt.Errorf("scfw proxy: invalid --http-status %d: must be between 200 and 599", httpStatus)
	}
	dash := cmd.ArgsLenAtDash()
	if dash == -1 {
		return fmt.Errorf("scfw proxy: missing \"--\" separator before command (usage: %s)", cmd.UseLine())
	}
	if dash != 0 {
		return fmt.Errorf("scfw proxy: unexpected argument(s) before \"--\": %s", strings.Join(args[:dash], " "))
	}
	if len(args) == dash {
		return errors.New("scfw proxy: no command specified after \"--\"")
	}
	managerName := filepath.Base(args[dash])
	if !supportedProxyManager(managerName) {
		return fmt.Errorf("scfw proxy: unsupported command %q: supported package managers are npm, yarn, pnpm, bun, pip, poetry, and uv", args[dash])
	}
	if err := validateProxyOperation(managerName, args[dash+1:]); err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}
	return nil
}

func runProxy(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	httpStatus, err := cmd.Flags().GetInt("http-status")
	if err != nil {
		return fmt.Errorf("scfw proxy: read --http-status: %w", err)
	}
	command := args[cmd.ArgsLenAtDash():]
	executable, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("scfw proxy: find %s executable: %w", filepath.Base(command[0]), err)
	}
	streams := registryproxy.Streams{
		Stdin:  cmd.InOrStdin(),
		Stdout: cmd.OutOrStdout(),
		Stderr: cmd.ErrOrStderr(),
	}
	options := registryproxy.Options{HTTPStatus: httpStatus, Evaluate: evaluateProxyPackage}
	if err := resolveOnWarning(); err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}
	var runErr error
	switch filepath.Base(command[0]) {
	case "npm":
		runErr = npmproxy.Run(cmd.Context(), executable, command[1:], streams, options)
	case "yarn", "yarnpkg":
		runErr = registryproxy.Run(cmd.Context(), &yarnproxy.Manager{}, executable, command[1:], streams, options)
	case "pnpm":
		runErr = registryproxy.Run(cmd.Context(), pnpmproxy.Manager{}, executable, command[1:], streams, options)
	case "bun":
		runErr = registryproxy.Run(cmd.Context(), &bunproxy.Manager{}, executable, command[1:], streams, options)
	case "pip", "pip3":
		runErr = registryproxy.Run(cmd.Context(), pipproxy.Manager{}, executable, command[1:], streams, options)
	case "poetry":
		runErr = registryproxy.Run(cmd.Context(), &poetryproxy.Manager{}, executable, command[1:], streams, options)
	case "uv":
		runErr = registryproxy.Run(cmd.Context(), uvproxy.Manager{}, executable, command[1:], streams, options)
	}
	if runErr != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("scfw proxy: %w", runErr)
	}
	return nil
}

func evaluateProxyPackage(ctx context.Context, pkg pm.Package) error {
	publishDate, err := ecosystem.ResolvePublishDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
	if err != nil {
		slog.Warn("failed to resolve package publish date", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version, "error", err)
	} else {
		pkg.PublishDate = publishDate
	}
	report, err := ddapi.EvaluateInstallTargets(ctx, false, pm.NewSet(pkg))
	if err != nil {
		return fmt.Errorf("evaluate %s %s: %w", pkg.Name, pkg.Version, err)
	}
	if decideFirewallAction(false, report.Outcome) != ddapi.OutcomeAllow {
		return fmt.Errorf("policy evaluation for %s %s returned %s", pkg.Name, pkg.Version, report.Outcome)
	}
	return nil
}

func supportedProxyManager(name string) bool {
	switch name {
	case "npm", "yarn", "yarnpkg", "pnpm", "bun", "pip", "pip3", "poetry", "uv":
		return true
	default:
		return false
	}
}

func validateProxyOperation(manager string, args []string) error {
	if len(args) == 0 {
		return errors.New("missing package-manager operation")
	}
	allowed := map[string]map[string]bool{
		"npm":     {"install": true, "i": true, "ci": true, "add": true, "update": true, "up": true},
		"yarn":    {"install": true},
		"yarnpkg": {"install": true},
		"pnpm":    {"install": true, "i": true},
		"bun":     {"install": true},
		"pip":     {"install": true},
		"pip3":    {"install": true},
		"poetry":  {"install": true, "sync": true},
		"uv":      {"install": true, "sync": true},
	}
	conflictingOptions := map[string]bool{
		"--registry": true, "--userconfig": true, "--globalconfig": true,
		"--config": true, "--config-file": true, "--index": true,
		"--default-index": true, "--index-url": true, "--extra-index-url": true,
		"-i": true, "--cwd": true, "--dir": true, "--config-dir": true,
		"--directory": true, "--project": true,
	}
	forbiddenOperations := map[string]bool{
		"publish": true, "upload": true, "config": true, "login": true,
		"logout": true, "token": true, "owner": true, "deprecate": true,
	}
	for _, argument := range args {
		name, _, _ := strings.Cut(strings.ToLower(argument), "=")
		if conflictingOptions[name] || argument == "-C" || strings.HasPrefix(name, "--@") && strings.HasSuffix(name, ":registry") {
			return fmt.Errorf("%s proxy mode does not support command-line registry option %q", manager, argument)
		}
	}
	operation := strings.ToLower(args[0])
	if strings.HasPrefix(operation, "-") {
		return fmt.Errorf("%s proxy mode requires the installation operation before command options", manager)
	}
	if forbiddenOperations[operation] {
		return fmt.Errorf("%s operation %q is not supported in install-only proxy mode", manager, args[0])
	}
	if manager == "uv" && operation == "pip" {
		if len(args) > 1 && strings.EqualFold(args[1], "install") {
			return nil
		}
		return errors.New("uv proxy mode supports only uv pip install or uv sync")
	}
	if allowed[manager][operation] {
		return nil
	}
	return fmt.Errorf("%s operation is not an installation command", manager)
}
