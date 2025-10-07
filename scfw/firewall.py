"""
Implements the supply-chain firewall's core `run` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import logging
import os
import sys

from scfw.constants import ALLOW_ON_WARNING_VAR, BLOCK_ON_WARNING_VAR
from scfw.logger import FirewallAction
from scfw.loggers import FirewallLoggers
from scfw.package_manager import UnsupportedVersionError
import scfw.package_managers as package_managers
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
    critical_report, warning_report = None, None

    loggers = FirewallLoggers()
    _log.info(f"Command: '{' '.join(args.command)}'")

    try:
        package_manager = package_managers.get_package_manager(args.package_manager, executable=args.executable)

        targets = package_manager.resolve_install_targets(args.command)
        _log.info(f"Command would install: [{', '.join(map(str, targets))}]")

        if targets:
            verifiers = FirewallVerifiers(package_manager.ecosystem())
            _log.info(f"Using package verifiers: [{', '.join(verifiers.names())}]")

            reports = verifiers.verify_packages(targets)
            critical_report = reports.get(FindingSeverity.CRITICAL)
            warning_report = reports.get(FindingSeverity.WARNING)

            if not args.dry_run and critical_report:
                loggers.log_firewall_action(
                    package_manager.ecosystem(),
                    package_manager.name(),
                    package_manager.executable(),
                    args.command,
                    list(critical_report.packages()),
                    action=FirewallAction.BLOCK,
                    verified=True,
                    warned=False,
                )
                print(critical_report)
                print("\nThe installation request was blocked. No changes have been made.")
                return 1 if args.error_on_block else 0

            if not args.dry_run and warning_report:
                print(warning_report)
                if _get_warning_action(args.allow_on_warning, args.block_on_warning) == FirewallAction.BLOCK:
                    loggers.log_firewall_action(
                        package_manager.ecosystem(),
                        package_manager.name(),
                        package_manager.executable(),
                        args.command,
                        list(warning_report.packages()),
                        action=FirewallAction.BLOCK,
                        verified=True,
                        warned=True,
                    )
                    print("The installation request was aborted. No changes have been made.")
                    return 1 if args.error_on_block else 0

        if args.dry_run:
            _log.info("Firewall dry-run mode enabled: command will not be run")
            if critical_report:
                print(critical_report)
            elif warning_report:
                print(warning_report)
            print("Dry-run: exiting without running command.")
            return 1 if (critical_report or warning_report) else 0

        loggers.log_firewall_action(
            package_manager.ecosystem(),
            package_manager.name(),
            package_manager.executable(),
            args.command,
            targets,
            action=FirewallAction.ALLOW,
            verified=True,
            warned=True if warning_report else False,
        )
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

        loggers.log_firewall_action(
            package_manager.ecosystem(),
            package_manager.name(),
            package_manager.executable(),
            args.command,
            targets=[],
            action=FirewallAction.ALLOW,
            verified=False,
            warned=False,
        )
        return package_manager.run_command(args.command)


def _get_warning_action(cli_allow_choice: bool, cli_block_choice: bool) -> FirewallAction:
    """
    Return the `FirewallAction` that should be taken for `WARNING`-level findings.

    Args:
        cli_allow_choice:
            A `bool` indicating whether the user selected `--allow-on-warning` on the command-line.
        cli_block_choice:
            A `bool` indicating whether the user selected `--block-on-warning` on the command-line.

    Returns:
        The `FirewallAction` that should be taken based on the user's configured choices or, if
        no choice has been made, on the user's runtime (interactive) decision.
    """
    if cli_block_choice or os.getenv(BLOCK_ON_WARNING_VAR):
        return FirewallAction.BLOCK
    if cli_allow_choice or os.getenv(ALLOW_ON_WARNING_VAR):
        return FirewallAction.ALLOW

    if not sys.stdin.isatty():
        _log.warning(
            "Non-interactive terminal and no predefined action for WARNING findings: defaulting to BLOCK"
        )
        return FirewallAction.BLOCK

    user_confirmed = inquirer.confirm("Proceed with installation?", default=False)
    return FirewallAction.ALLOW if user_confirmed else FirewallAction.BLOCK
