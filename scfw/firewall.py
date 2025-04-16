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
        warned = False

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
                    ecosystem,
                    command.executable(),
                    args.command,
                    list(critical_report),
                    action=FirewallAction.BLOCK,
                    warned=False
                )
                print(verify.show_verification_report(critical_report))
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if (warning_report := reports.get(FindingSeverity.WARNING)):
                print(verify.show_verification_report(warning_report))
                warned = True

                if not (inquirer.confirm("Proceed with installation?", default=False)):
                    _log_firewall_action(
                        logs,
                        ecosystem,
                        command.executable(),
                        args.command,
                        list(warning_report),
                        action=FirewallAction.BLOCK,
                        warned=warned
                    )
                    print("The installation request was aborted. No changes have been made.")
                    return 0

        if args.dry_run:
            _log.info("Firewall dry-run mode enabled: command will not be run")
            print("Dry-run: exiting without running command.")
        else:
            _log_firewall_action(
                logs,
                ecosystem,
                command.executable(),
                args.command,
                targets,
                action=FirewallAction.ALLOW,
                warned=warned
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
    ecosystem: ECOSYSTEM,
    executable: str,
    command: list[str],
    targets: list[InstallTarget],
    action: FirewallAction,
    warned: bool
):
    """
    Log a firewall action across a given set of client loggers.

    Args:
        ecosystem: The ecosystem of the inspected package manager command.
        executable: The executable used to execute the inspected package manager command.
        command: The package manager command line provided to the firewall.
        targets: The installation targets relevant to firewall's action.
        action: The action taken by the firewall.
        warned: Indicates whether the user was warned about findings and prompted for approval.
    """
    # One would like to use `map` for this, but it is lazily evaluated
    for log in logs:
        log.log(ecosystem, executable, command, targets, action, warned)
