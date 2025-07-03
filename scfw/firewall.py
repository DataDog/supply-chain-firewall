"""
Implements the supply-chain firewall's core `run` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import logging

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
        An integer status code, 0 or 1.
    """
    try:
        warned = False

        loggers = FirewallLoggers()
        _log.info(f"Command: '{' '.join(args.command)}'")

        package_manager = package_managers.get_package_manager(args.package_manager, executable=args.executable)

        targets = package_manager.resolve_install_targets(args.command)
        _log.info(f"Command would install: [{', '.join(map(str, targets))}]")

        if targets:
            verifiers = FirewallVerifiers()
            _log.info(
                f"Using package verifiers: [{', '.join(verifiers.names())}]"
            )

            reports = verifiers.verify_packages(targets)

            if (critical_report := reports.get(FindingSeverity.CRITICAL)):
                loggers.log_firewall_action(
                    package_manager.ecosystem(),
                    package_manager.name(),
                    package_manager.executable(),
                    args.command,
                    list(critical_report.packages()),
                    action=FirewallAction.BLOCK,
                    warned=False
                )
                print(critical_report)
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if (warning_report := reports.get(FindingSeverity.WARNING)):
                print(warning_report)
                warned = True

                if not args.dry_run and not inquirer.confirm("Proceed with installation?", default=False):
                    loggers.log_firewall_action(
                        package_manager.ecosystem(),
                        package_manager.name(),
                        package_manager.executable(),
                        args.command,
                        list(warning_report.packages()),
                        action=FirewallAction.BLOCK,
                        warned=warned
                    )
                    print("The installation request was aborted. No changes have been made.")
                    return 0

        if args.dry_run:
            _log.info("Firewall dry-run mode enabled: command will not be run")
            print("Dry-run: exiting without running command.")
        else:
            loggers.log_firewall_action(
                package_manager.ecosystem(),
                package_manager.name(),
                package_manager.executable(),
                args.command,
                targets,
                action=FirewallAction.ALLOW,
                warned=warned
            )
            package_manager.run_command(args.command)
        return 0

    except UnsupportedVersionError as e:
        _log.error(f"Incompatible package manager version: {e}")
        return 0

    except Exception as e:
        _log.error(e)
        return 1
