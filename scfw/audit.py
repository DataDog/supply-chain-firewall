"""
Implements Supply Chain Firewall's `audit` subcommand.
"""

from argparse import Namespace
import logging

from scfw.loggers import FirewallLoggers
import scfw.package_managers as package_managers
from scfw.report import show_reports
from scfw.verifier import FindingSeverity
from scfw.verifiers import FirewallVerifiers

_log = logging.getLogger(__name__)


def run_audit(args: Namespace) -> int:
    """
    Audit installed packages using Supply Chain Firewall's verifiers.

    Args:
        args: A `Namespace` containing the parsed `audit` subcommand command line.

    Returns:
        An integer status code indicating normal exit.
    """
    package_manager = package_managers.get_package_manager(args.package_manager, executable=args.executable)

    if (installed_packages := package_manager.get_installed_packages()):
        _log.info(f"Installed packages: [{', '.join(sorted(map(str, installed_packages)))}]")

        verifiers = FirewallVerifiers(package_manager.ecosystem())
        _log.info(f"Using package verifiers: [{', '.join(verifiers.names())}]")

        report = verifiers.verify_packages(installed_packages)
        FirewallLoggers().log_audit(
            package_manager.ecosystem(),
            package_manager.name(),
            package_manager.executable(),
            report,
        )

        output = show_reports(
            [report.get_findings(severity) for severity in FindingSeverity],
            report.get_unverifiable(),
        )
        if output:
            print(output)
        else:
            print("No issues found.")

    return 0
