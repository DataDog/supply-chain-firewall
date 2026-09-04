// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/git"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// onWarningVar is the environment variable that resolves the firewall's on-warning
// action, taking precedence over --allow-on-warning/--block-on-warning when set.
const onWarningVar = "SCFW_ON_WARNING"

// onWarning is the resolved firewall action for a WARN outcome, computed by
// resolveOnWarning from --allow-on-warning/--block-on-warning and SCFW_ON_WARNING.
// WARN means neither was set, deferring to the interactive/non-interactive fallback.
var onWarning = ddapi.OutcomeWarn

var runCmd = &cobra.Command{
	Use:     "run [flags] -- <command>",
	Short:   "Run a package manager command through Supply Chain Firewall.",
	Args:    validateRunArgs,
	PreRunE: func(cmd *cobra.Command, args []string) error { return rejectFlagLikeValues(cmd) },
	RunE:    runFirewall,
}

var (
	allowOnWarning bool
	blockOnWarning bool
	errorOnBlock   bool
	executable     string
)

func init() {
	runCmd.Flags().BoolVar(&errorOnBlock, "error-on-block", false, "Treat blocked commands as errors (useful for scripting).")
	runCmd.Flags().StringVar(&executable, "executable", "", "Package manager executable to use for running commands (default: environmentally determined).")
	runCmd.Flags().BoolVar(&allowOnWarning, "allow-on-warning", false, "Non-interactively allow commands with only warning-level findings.")
	runCmd.Flags().BoolVar(&blockOnWarning, "block-on-warning", false, "Non-interactively block commands with only warning-level findings.")
	runCmd.MarkFlagsMutuallyExclusive("allow-on-warning", "block-on-warning")
}

// resolveOnWarning computes onWarning from --allow-on-warning/--block-on-warning and
// SCFW_ON_WARNING, which takes precedence over the flags when set.
func resolveOnWarning() error {
	if allowOnWarning {
		onWarning = ddapi.OutcomeAllow
	}
	if blockOnWarning {
		onWarning = ddapi.OutcomeBlock
	}

	switch val := strings.ToLower(os.Getenv(onWarningVar)); val {
	case "":
	case strings.ToLower(string(ddapi.OutcomeAllow)):
		onWarning = ddapi.OutcomeAllow
	case strings.ToLower(string(ddapi.OutcomeBlock)):
		onWarning = ddapi.OutcomeBlock
	default:
		return fmt.Errorf("invalid %s value %q (must be \"allow\" or \"block\")", onWarningVar, val)
	}
	return nil
}

func validateRunArgs(cmd *cobra.Command, args []string) error {
	dash := cmd.ArgsLenAtDash()
	if dash == -1 {
		return fmt.Errorf("scfw run: missing \"--\" separator before command (usage: %s)", cmd.UseLine())
	}
	if dash != 0 {
		return fmt.Errorf("scfw run: unexpected argument(s) before \"--\": %s", strings.Join(args[:dash], " "))
	}
	if len(args) == dash {
		return errors.New("scfw run: no command specified after \"--\"")
	}
	return nil
}

func runFirewall(cmd *cobra.Command, args []string) error {
	// Suppress usage for errors from here on, but not for validateRunArgs.
	cmd.SilenceUsage = true

	if err := resolveOnWarning(); err != nil {
		return fmt.Errorf("scfw run: %w", err)
	}

	// Captured before any package installation work, for reporting.
	installTimestamp := time.Now().UTC()

	isInteractive := term.IsTerminal(int(os.Stdin.Fd()))

	cmdArgs := args[cmd.ArgsLenAtDash():]
	packageManagerName := filepath.Base(cmdArgs[0])
	slog.Debug("preparing package manager command", "package_manager", packageManagerName, "command", cmdArgs)

	packageManagerFactory, ok := findPackageManagerFactory(packageManagerName)
	if !ok {
		return fmt.Errorf("scfw run: unsupported command %q", cmdArgs[0])
	}
	packageManager, err := packageManagerFactory.New(cmd.Context(), cmdArgs[0], executable)
	if err != nil {
		return fmt.Errorf("scfw run: %w", err)
	}

	slog.Debug("resolving package installation targets", "package_manager", packageManagerName)
	installTargets, err := packageManager.ResolveInstallTargets(cmd.Context(), cmdArgs[1:])
	if err != nil {
		return fmt.Errorf("scfw run: %w", err)
	}

	slog.Info("resolved install targets", "targets", slices.Collect(installTargets.Items()))

	var evaluationReport ddapi.ScfwPolicyEvaluationReport
	if installTargets.Len() == 0 {
		// Nothing to evaluate: the API requires a non-empty packages list, and
		// there's nothing a policy decision could act on anyway.
		evaluationReport = ddapi.ScfwPolicyEvaluationReport{Outcome: ddapi.OutcomeAllow, Results: []ddapi.PackageEvaluationResult{}}
	} else {
		slog.Debug("evaluating package installation targets", "count", installTargets.Len())
		evaluationReport, err = ddapi.EvaluateInstallTargets(cmd.Context(), isInteractive, installTargets)
		if err != nil {
			return fmt.Errorf("scfw run: %w", err)
		}
	}
	slog.Debug("resolved firewall policy outcome", "outcome", evaluationReport.Outcome)

	// Explain the outcome before anything else, so the user sees why a command was
	// blocked or flagged before any interactive prompt asks them to decide.
	if details := formatEvaluationDetails(evaluationReport); details != "" {
		fmt.Fprint(os.Stderr, details)
	}

	action := decideFirewallAction(isInteractive, evaluationReport.Outcome)
	gitMetadata := discoverGitMetadata(packageManager, cmdArgs[1:])

	if err := ddapi.ReportFirewallOutcome(
		cmd.Context(),
		installTimestamp,
		cmdArgs,
		packageManagerName,
		packageManager.Executable(),
		gitMetadata.RepositoryURL,
		installTargets,
		evaluationReport,
		action,
	); err != nil {
		slog.Warn("failed to report firewall outcome", "error", err)
	}

	switch action {
	case ddapi.OutcomeAllow:
		slog.Debug("running approved package manager command", "package_manager", packageManagerName)
		if err := packageManager.RunCommand(cmd.Context(), cmdArgs[1:]); err != nil {
			// Preserve the wrapped command's own exit code.
			if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
				os.Exit(exitErr.ExitCode())
			}
			slog.Error("failed to run command", "error", err)
			os.Exit(-1)
		}
		return nil
	default:
		fmt.Fprintln(os.Stderr, "The command was blocked. No changes have been made.")
		if errorOnBlock {
			return errors.New("scfw run: command blocked")
		}
		return nil
	}
}

func discoverGitMetadata(packageManager pm.PackageManager, command []string) git.Metadata {
	projectDirectory, err := packageManager.ProjectDirectory(command)
	if err != nil {
		slog.Debug("failed to resolve package manager project directory", "error", err)
		return git.Metadata{}
	}

	metadata, err := git.Discover(projectDirectory)
	if err != nil {
		slog.Debug("failed to discover Git repository metadata", "error", err)
		return git.Metadata{}
	}
	return metadata
}

// decideFirewallAction resolves a policy evaluation Outcome into the firewall's action.
// ALLOW and BLOCK pass through unchanged. ERROR is coerced to WARN, and WARN is
// resolved interactively: BLOCK in a non-interactive context, otherwise the user is
// prompted to decide. Anything else is coerced to BLOCK.
func decideFirewallAction(isInteractive bool, outcome ddapi.Outcome) ddapi.Outcome {
	if outcome == ddapi.OutcomeError {
		slog.Info("received an ERROR outcome; coercing to WARN")
		outcome = ddapi.OutcomeWarn
	}

	switch outcome {
	case ddapi.OutcomeAllow, ddapi.OutcomeBlock:
		return outcome
	case ddapi.OutcomeWarn:
		return resolveWarningAction(isInteractive)
	default:
		slog.Warn("received an unexpected policy evaluation outcome; blocking the command", "outcome", outcome)
		return ddapi.OutcomeBlock
	}
}

// resolveWarningAction decides the firewall's action in response to a WARN outcome.
// If onWarning was resolved from --allow-on-warning/--block-on-warning or
// SCFW_ON_WARNING, that decision is used. Otherwise, in a non-interactive context,
// it always blocks; otherwise it prompts the user to decide.
func resolveWarningAction(isInteractive bool) ddapi.Outcome {
	if onWarning != ddapi.OutcomeWarn {
		return onWarning
	}

	if !isInteractive {
		slog.Warn("received a WARN outcome in a non-interactive context; blocking the command")
		return ddapi.OutcomeBlock
	}

	fmt.Fprint(os.Stderr, "Proceed with installation? [y/N]: ")
	return parseInstallConfirmation(os.Stdin)
}

// formatEvaluationDetails explains a non-ALLOW outcome to the user, describing the
// offending packages and the policy matches/verifier failures behind them. It returns ""
// for ALLOW, and a non-empty explanation for anything else (BLOCK, WARN, or an unexpected
// outcome), erring on the side of surfacing detail whenever the outcome isn't
// affirmatively ALLOW.
func formatEvaluationDetails(report ddapi.ScfwPolicyEvaluationReport) string {
	if report.Outcome == ddapi.OutcomeAllow {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Policy evaluation outcome: %s\n", report.Outcome)
	for _, result := range report.Results {
		if result.Outcome != report.Outcome {
			continue
		}
		fmt.Fprintf(&b, "  - %s %s@%s\n", result.Ecosystem, result.PackageName, result.PackageVersion)
		for _, policy := range result.MatchedPolicy {
			if policy.Rule != "" {
				fmt.Fprintf(&b, "      %s: %s\n", policy.Type, policy.Rule)
			} else {
				fmt.Fprintf(&b, "      %s\n", policy.Type)
			}
		}
		for _, f := range result.Failures {
			fmt.Fprintf(&b, "      %s: failed to evaluate (%s)\n", f.Verifier, f.Error)
		}
	}
	return b.String()
}

// parseInstallConfirmation reads a single line from r and interprets it as the user's
// answer to the installation confirmation prompt. Anything other than "y"/"yes"
// (case-insensitive), or a read error, is treated as a decline.
func parseInstallConfirmation(r io.Reader) ddapi.Outcome {
	answer, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		slog.Warn("failed to read installation confirmation; blocking the command", "error", err)
		return ddapi.OutcomeBlock
	}

	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return ddapi.OutcomeAllow
	default:
		return ddapi.OutcomeBlock
	}
}
