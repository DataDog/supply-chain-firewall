"""
Provides the supply-chain firewall's main routine.
"""

import logging
import time

import scfw.cli as cli
from scfw.command import UnsupportedVersionError
import scfw.commands as commands
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
import scfw.loggers as loggers
from scfw.verifier import FindingSeverity
import scfw.verifiers as verifs
import scfw.verify as verify
from scfw.target import InstallTarget

# Firewall root logger configured to write to stderr
_log = logging.getLogger()
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
_log.addHandler(_handler)


def run_firewall() -> int:
    """
    The main routine for the supply-chain firewall.

    Returns:
        An integer exit code (0 or 1).
    """
    try:
        args, help = cli.parse_command_line()
        if not args.command:
            print(help)
            return 0

        _log.setLevel(args.log_level)
        logs = loggers.get_firewall_loggers()

        _log.info(f"Starting supply-chain firewall on {time.asctime(time.localtime())}")
        _log.info(f"Command: '{' '.join(args.command)}'")
        _log.debug(f"Command line: {vars(args)}")

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
                _log_all(
                    logs,
                    FirewallAction.Block,
                    ecosystem,
                    args.command,
                    list(critical_report.install_targets())
                )
                print(critical_report)
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if (warning_report := reports.get(FindingSeverity.WARNING)):
                print(warning_report)
                if _abort_on_warning():
                    _log_all(
                        logs,
                        FirewallAction.Abort,
                        ecosystem,
                        args.command,
                        list(warning_report.install_targets())
                    )
                    print("The installation request was aborted. No changes have been made.")
                    return 0

        if args.dry_run:
            _log.info("Firewall dry-run mode enabled: command will not be run")
            print("Dry-run: exiting without running command.")
        else:
            _log_all(
                logs,
                FirewallAction.Allow,
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


def _log_all(
    logs: list[FirewallLogger],
    action: FirewallAction,
    ecosystem: ECOSYSTEM,
    command: list[str],
    targets: list[InstallTarget],
):
    """
    Lorem ipsum dolor sic amet.
    """
    for log in logs:
        log.log(action, ecosystem, command, targets)


def _abort_on_warning() -> bool:
    """
    Prompt the user for confirmation of whether or not to proceed with the
    installation request in the case that there were `WARNING` findings.
    """
    try:
        while (confirm := input("Proceed with installation? (y/N): ")) not in {'y', 'N', ''}:
            pass
        return confirm != 'y'
    except KeyboardInterrupt:
        return True
    except Exception:
        return True
