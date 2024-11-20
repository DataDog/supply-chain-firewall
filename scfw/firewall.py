"""
Implements the supply-chain firewall's core `run` subcommand.
"""

from argparse import Namespace
import logging
import time

from scfw.command import UnsupportedVersionError
import scfw.commands as commands
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
import scfw.loggers as loggers
from scfw.verifier import FindingSeverity
import scfw.verifiers as verifs
import scfw.verify as verify
from scfw.target import InstallTarget


def run_firewall(args: Namespace, help: str) -> int:
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
    log = _root_logger()

    try:
        if not args.command:
            print(help)
            return 0

        log.setLevel(args.log_level)
        logs = loggers.get_firewall_loggers()

        log.info(f"Starting supply-chain firewall on {time.asctime(time.localtime())}")
        log.info(f"Command: '{' '.join(args.command)}'")
        log.debug(f"Command line: {vars(args)}")

        ecosystem, command = commands.get_package_manager_command(args.command, executable=args.executable)
        targets = command.would_install()
        log.info(f"Command would install: [{', '.join(map(str, targets))}]")

        if targets:
            verifiers = verifs.get_install_target_verifiers()
            log.info(
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
                if _abort_on_warning():
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
            log.info("Firewall dry-run mode enabled: command will not be run")
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
        log.error(f"Incompatible package manager version: {e}")
        return 0

    except Exception as e:
        log.error(e)
        return 1


def _root_logger() -> logging.Logger:
    """
    Configure the root logger and return a handle to it.

    Returns:
        A handle to the configured root logger.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    log = logging.getLogger()
    log.addHandler(handler)

    return log


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


def _abort_on_warning() -> bool:
    """
    Prompt the user for confirmation of whether or not to proceed with the
    installation request in the case that there were `WARNING` findings.

    Returns:
        A `bool` indicating whether the user decided to proceed with the
        command after warning.
    """
    try:
        while (confirm := input("Proceed with installation? (y/N): ")) not in {'y', 'N', ''}:
            pass
        return confirm != 'y'
    except KeyboardInterrupt:
        return True
    except Exception:
        return True
