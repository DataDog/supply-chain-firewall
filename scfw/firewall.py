"""
Implements the supply-chain firewall's core `run` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import logging

from scfw.command import UnsupportedVersionError
import scfw.commands as commands
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
import scfw.loggers as loggers
from scfw.verifier import FindingSeverity
import scfw.verifiers as verifs
import scfw.verify as verify
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)


def run_firewall(args: Namespace) -> int:
    """
    Run a package manager command through the supply-chain firewall.

    Args:
        args:
            A `Namespace` parsed from a `run` subcommand command line containing
            a `command` to run through the firewall.
        help: A help message to print in the case of early returns.

    Returns:
        An integer status code, 0 or 1.
    """
    try:
        logs = loggers.get_firewall_loggers()
        _log.info(f"Command: '{' '.join(args.command)}'")

        ecosystem, command = commands.get_package_manager_command(args.command, executable=args.executable)
        targets = command.would_install()
        _log.info(f"Command would install: [{', '.join(map(str, targets))}]")

        if targets:
            verifiers = verifs.get_install_target_verifiers()
            _log.info(
                f"Using installation target verifiers: [{', '.join(v.name() for v in verifiers)}]"
            )

            reports = verify.verify_install_targets(verifiers, targets)

            if (critical_report := reports.get(FindingSeverity.CRITICAL)):
                _log_firewall_action(
                    logs,
                    FirewallAction.BLOCK,
                    ecosystem,
                    args.command,
                    list(critical_report)
                )
                print(verify.show_verification_report(critical_report))
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if (warning_report := reports.get(FindingSeverity.WARNING)):
                print(verify.show_verification_report(warning_report))
                if not (inquirer.confirm("Proceed with installation?", default=False)):
                    _log_firewall_action(
                        logs,
                        FirewallAction.ABORT,
                        ecosystem,
                        args.command,
                        list(warning_report)
                    )
                    print("The installation request was aborted. No changes have been made.")
                    return 0

        if args.dry_run:
            _log.info("Firewall dry-run mode enabled: command will not be run")
            print("Dry-run: exiting without running command.")
        else:
            _log_firewall_action(
                logs,
                FirewallAction.ALLOW,
                ecosystem,
                args.command,
                targets
            )
            command.run()
        return 0

    except UnsupportedVersionError as e:
        _log.error(f"Incompatible package manager version: {e}")
        return 0

    except Exception as e:
        _log.error(e)
        return 1


def _log_firewall_action(
    logs: list[FirewallLogger],
    action: FirewallAction,
    ecosystem: ECOSYSTEM,
    command: list[str],
    targets: list[InstallTarget],
):
    """
    Log a firewall action across a given set of client loggers.

    Args:
        action: The action taken by the firewall.
        ecosystem: The ecosystem of the inspected package manager command.
        command: The package manager command line provided to the firewall.
        targets:
            The installation targets relevant to firewall's action.
    """
    # One would like to use `map` for this, but it is lazily evaluated
    for log in logs:
        log.log(action, ecosystem, command, targets)
