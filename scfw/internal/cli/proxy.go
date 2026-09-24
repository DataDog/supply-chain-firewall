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
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/git"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	httpsproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/packagemanager"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy -- <command>",
	Short: "Run a supported package manager through an HTTPS inspection proxy.",
	Args:  validateProxyArgs,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		return rejectFlagLikeValues(cmd)
	},
	RunE: runProxy,
}

var (
	proxyAllowOnWarning bool
	proxyBlockOnWarning bool
	proxyErrorOnBlock   bool
)

func init() {
	proxyCmd.Flags().BoolVar(&proxyErrorOnBlock, "error-on-block", false, "Treat blocked commands as errors (useful for scripting).")
	proxyCmd.Flags().BoolVar(&proxyAllowOnWarning, "allow-on-warning", false, "Non-interactively allow packages with only warning-level findings.")
	proxyCmd.Flags().BoolVar(&proxyBlockOnWarning, "block-on-warning", false, "Non-interactively block packages with only warning-level findings.")
	proxyCmd.MarkFlagsMutuallyExclusive("allow-on-warning", "block-on-warning")
}

func validateProxyArgs(cmd *cobra.Command, args []string) error {
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
	return nil
}

func runProxy(cmd *cobra.Command, args []string) (runErr error) {
	cmd.SilenceUsage = true
	if err := resolveProxyOnWarning(); err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}

	mode, err := resolveEvaluationMode()
	if err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}
	noteLocalEvaluation(mode)
	evaluator, err := newEvaluator(cmd.Context(), mode)
	if err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}
	reporter := newReporter(mode)

	command := args[cmd.ArgsLenAtDash():]
	policy := &proxyPackagePolicy{
		cmd:                cmd,
		evaluator:          evaluator,
		reporter:           reporter,
		resolvePublishDate: ecosystem.ResolvePublishDate,
		isInteractive:      term.IsTerminal(int(os.Stdin.Fd())),
		installTimestamp:   time.Now().UTC(),
		command:            command,
		packageManagerName: filepath.Base(command[0]),
		repository:         discoverProxyGitMetadata().RepositoryURL,
		decisions:          make(map[packageVersion]packageDecision),
	}

	server, err := httpsproxy.Start(proxyOptions(policy))
	if err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}
	defer func() {
		if closeErr := server.Close(); runErr == nil && closeErr != nil {
			runErr = fmt.Errorf("scfw proxy: %w", closeErr)
		}
	}()

	child, err := packagemanager.Command(cmd.Context(), command, server.URL(), server.CertificatePath())
	if err != nil {
		return fmt.Errorf("scfw proxy: %w", err)
	}
	policy.executable = child.Path
	child.Stdin = cmd.InOrStdin()
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = cmd.ErrOrStderr()

	childErr := child.Run()
	policyErr, blocked := policy.result()
	if policyErr != nil {
		return fmt.Errorf("scfw proxy: %w", policyErr)
	}
	if blocked {
		if proxyErrorOnBlock {
			return errors.New("scfw proxy: package blocked")
		}
		return nil
	}
	if childErr != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](childErr); ok {
			return fmt.Errorf("scfw proxy: package manager exited with status %d: %w", exitErr.ExitCode(), childErr)
		}
		return fmt.Errorf("scfw proxy: run package manager: %w", childErr)
	}
	return nil
}

func resolveProxyOnWarning() error {
	return resolveOnWarningFlags(proxyAllowOnWarning, proxyBlockOnWarning)
}

type publishDateResolver func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error)

type packageVersion struct {
	ecosystem ecosystem.Ecosystem
	name      string
	version   string
}

func proxyOptions(policy *proxyPackagePolicy) httpsproxy.Options {
	return httpsproxy.Options{
		OnRequest: policy.handleRequest,
	}
}

type packageDecision struct {
	rejection error
}

// proxyPackagePolicy evaluates and reports each distinct package artifact before
// allowing its request to reach the registry. The mutex deliberately spans the
// evaluation: package managers fetch concurrently, while warning prompts and
// policy decisions must remain ordered and each package must be evaluated once.
type proxyPackagePolicy struct {
	cmd                *cobra.Command
	evaluator          evaluation.Evaluator
	reporter           evaluation.Reporter
	resolvePublishDate publishDateResolver
	isInteractive      bool
	installTimestamp   time.Time
	command            []string
	packageManagerName string
	executable         string
	repository         string

	mutex      sync.Mutex
	decisions  map[packageVersion]packageDecision
	fatalError error
	blocked    bool
}

func (policy *proxyPackagePolicy) handleRequest(request httpsproxy.Request) error {
	pkg, ok := packagemanager.PackageFromArtifactURL(request.URL)
	if !ok {
		return nil
	}

	key := packageVersion{ecosystem: pkg.Ecosystem, name: pkg.Name, version: pkg.Version}
	policy.mutex.Lock()
	defer policy.mutex.Unlock()
	if decision, found := policy.decisions[key]; found {
		return decision.rejection
	}
	if policy.fatalError != nil {
		return errors.New("package evaluation failed")
	}

	publishDate, err := policy.resolvePublishDate(
		policy.cmd.Context(), pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source,
	)
	if err != nil {
		slog.Warn("failed to resolve package publish date", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version, "error", err)
	} else {
		pkg.PublishDate = publishDate
	}
	installTargets := pm.NewSet(pkg)

	evaluationReport, err := policy.evaluator.EvaluateInstallTargets(policy.cmd.Context(), policy.isInteractive, installTargets)
	if err != nil {
		policy.fatalError = fmt.Errorf("evaluate %s %s@%s: %w", pkg.Ecosystem, pkg.Name, pkg.Version, err)
		decision := packageDecision{rejection: errors.New("package evaluation failed")}
		policy.decisions[key] = decision
		return decision.rejection
	}

	switch evaluationReport.Outcome {
	case evaluation.OutcomeBlock, evaluation.OutcomeWarn:
		if _, err := fmt.Fprintf(
			policy.cmd.OutOrStdout(), "%s %s %s@%s\n",
			evaluationReport.Outcome, pkg.Ecosystem, pkg.Name, pkg.Version,
		); err != nil {
			slog.Warn("failed to write package policy outcome", "error", err)
		}
	}
	if details := formatEvaluationDetails(evaluationReport); details != "" {
		if _, err := fmt.Fprint(policy.cmd.ErrOrStderr(), details); err != nil {
			slog.Warn("failed to write policy evaluation details", "error", err)
		}
	}
	action := decideFirewallAction(policy.isInteractive, evaluationReport.Outcome)
	if err := policy.reporter.ReportFirewallOutcome(
		policy.cmd.Context(),
		policy.installTimestamp,
		policy.command,
		policy.packageManagerName,
		policy.executable,
		policy.repository,
		installTargets,
		evaluationReport,
		action,
	); err != nil {
		slog.Warn("failed to report firewall outcome", "error", err)
	}

	decision := packageDecision{}
	if action != evaluation.OutcomeAllow {
		policy.blocked = true
		decision.rejection = fmt.Errorf("package blocked by Supply Chain Firewall: %s %s@%s", pkg.Ecosystem, pkg.Name, pkg.Version)
	}
	policy.decisions[key] = decision
	return decision.rejection
}

func (policy *proxyPackagePolicy) result() (error, bool) {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()
	return policy.fatalError, policy.blocked
}

func discoverProxyGitMetadata() git.Metadata {
	workingDirectory, err := os.Getwd()
	if err != nil {
		slog.Debug("failed to determine working directory for Git metadata", "error", err)
		return git.Metadata{}
	}
	metadata, err := git.Discover(workingDirectory)
	if err != nil {
		slog.Debug("failed to discover Git repository metadata", "error", err)
		return git.Metadata{}
	}
	return metadata
}
