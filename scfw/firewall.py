"""
Implements the supply-chain firewall's core `run` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import logging

from scfw.command import UnsupportedVersionError
import scfw.commands as commands
from scfw.logger import FirewallAction
from scfw.loggers import FirewallLoggers
from scfw.verifier import FindingSeverity
import scfw.verifiers as verifs
import scfw.verify as verify

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

        command = commands.get_package_manager_command(args.command, executable=args.executable)
        targets = command.would_install()
        _log.info(f"Command would install: [{', '.join(map(str, targets))}]")

        if targets:
            verifiers = verifs.get_install_target_verifiers()
            _log.info(
                f"Using installation target verifiers: [{', '.join(v.name() for v in verifiers)}]"
            )

            reports = verify.verify_install_targets(verifiers, targets)

            if (critical_report := reports.get(FindingSeverity.CRITICAL)):
                loggers.log(
                    command.ecosystem(),
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
                    loggers.log(
                        command.ecosystem(),
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
            loggers.log(
                command.ecosystem(),
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
