"""
Implements the supply-chain firewall's core `run` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import logging
import os
import sys
from typing import Optional

from scfw.constants import ON_WARNING_VAR
from scfw.logger import FirewallAction, FirewallRunSummary
from scfw.loggers import FirewallLoggers
from scfw.package_manager import UnsupportedVersionError
import scfw.package_managers as package_managers
from scfw.report import FindingsReport, VerificationReport, show_reports
from scfw.verifier import FindingSeverity
from scfw.verifiers import FirewallVerifiers

_log = logging.getLogger(__name__)


def run_firewall(args: Namespace) -> int:
    """
    Run a package manager command through the supply-chain firewall.

    Args:
        args:
            A `Namespace` parsed from a `run` subcommand command line containing a
            command to run through the firewall.

    Returns:
        An integer status code indicating normal or error exit.
    """
    package_manager = None

    loggers = FirewallLoggers()
    _log.info(f"Command: '{' '.join(args.command)}'")

    try:
        package_manager = package_managers.get_package_manager(args.package_manager, executable=args.executable)

        install_targets = package_manager.resolve_install_targets(args.command)
        _log.info(f"Command would install: [{', '.join(map(str, install_targets))}]")

        if install_targets:
            verifiers = FirewallVerifiers(package_manager.ecosystem())
            _log.info(f"Using package verifiers: [{', '.join(verifiers.names())}]")

            report = verifiers.verify_packages(install_targets)
        else:
            report = VerificationReport()

        warning_action = _get_warning_action(args.allow_on_warning, args.block_on_warning)
        action, warned, relevant_findings = _determine_firewall_action(report, warning_action)

        output = show_reports(
            [relevant_findings] if relevant_findings else [],
            report.get_unverified(),
        )
        if output:
            print(output)

        if args.dry_run:
            _log.info("Firewall dry-run mode enabled: command will not be run")
            print("Dry-run: exiting without running command.")
            return 1 if args.error_on_block and action == FirewallAction.BLOCK else 0

        # This only occurs when `warned=True` and no automatic action was inferrable
        if action is None:
            user_confirmed = inquirer.confirm("Proceed with installation?", default=False)
            action = FirewallAction.ALLOW if user_confirmed else FirewallAction.BLOCK

        loggers.log_firewall_run(
            package_manager.ecosystem(),
            package_manager.name(),
            package_manager.executable(),
            FirewallRunSummary(
                args.command,
                install_targets,
                report,
                relevant_findings,
                warned,
                action,
            ),
        )

        match action:
            case FirewallAction.BLOCK:
                print("\nThe command was blocked. No changes have been made.")
                return 1 if args.error_on_block else 0

            case FirewallAction.ALLOW:
                return package_manager.run_command(args.command)

    except UnsupportedVersionError as e:
        if not args.allow_unsupported:
            _log.error(e)
            _log.error(
                "Upgrade to a supported version or rerun with --allow-unsupported to bypass verification (use caution)"
            )
            return 0

        _log.info(f"Unsupported package manager version: {e}")
        _log.info(f"Unsupported versions allowed: running command '{' '.join(args.command)}' without verification")

        if not package_manager:
            raise RuntimeError("Failed to initialize package manager handle: cannot run command")

        loggers.log_firewall_run(
            package_manager.ecosystem(),
            package_manager.name(),
            package_manager.executable(),
            FirewallRunSummary(
                args.command,
                install_targets=None,
                report=None,
                relevant_findings=None,
                warned=False,
                action=FirewallAction.ALLOW,
            ),
        )
        return package_manager.run_command(args.command)


def _determine_firewall_action(
    report: VerificationReport,
    warning_action: Optional[FirewallAction]
) -> tuple[Optional[FirewallAction], bool, Optional[FindingsReport]]:
    """
    Determine the firewall action and its relevant findings from the given inputs.

    Args:
        report: The `VerificationReport` on whose basis the action will be decided.
        warning_action:
            The (possibly undefined) action to take in the case that `report`
            contains only warning-level findings or unverifiable packages.

    Returns:
        Lorem ipsum dolor sit amet.
    """
    critical_findings = report.get_findings(FindingSeverity.CRITICAL)
    warning_findings = report.get_findings(FindingSeverity.WARNING)

    # Critical findings => BLOCK
    if critical_findings:
        return FirewallAction.BLOCK, False, critical_findings

    # No critical or warning findings and no unverifiable packages => ALLOW
    if not (warning_findings or report.get_unverified()):
        return FirewallAction.ALLOW, False, None

    # Warning findings or unverifiable packages => configured warning action (or user confirmation)
    return warning_action, True, warning_findings if warning_findings else None


def _get_warning_action(cli_allow_choice: bool, cli_block_choice: bool) -> Optional[FirewallAction]:
    """
    Return the `FirewallAction` that would be automatically taken for `WARNING`-level findings
    based on available command-line options and environmental settings.

    Args:
        cli_allow_choice:
            A `bool` indicating whether the user selected `--allow-on-warning` on the command-line.
        cli_block_choice:
            A `bool` indicating whether the user selected `--block-on-warning` on the command-line.

    Returns:
        The `FirewallAction` that would be automatically taken based on the available settings or
        `None` if an automatic action could not be determined. In this case, the user's runtime
        (interactive) decision determines the action taken.
    """
    if cli_block_choice:
        return FirewallAction.BLOCK
    if cli_allow_choice:
        return FirewallAction.ALLOW

    if (action := os.getenv(ON_WARNING_VAR)):
        try:
            return FirewallAction.from_string(action)
        except Exception:
            _log.warning(f"Ignoring invalid firewall action {ON_WARNING_VAR}='{action}'")

    if not sys.stdin.isatty():
        _log.warning(
            "Non-interactive terminal and no predefined action for WARNING findings: defaulting to BLOCK"
        )
        return FirewallAction.BLOCK

    return None
