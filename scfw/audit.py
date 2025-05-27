"""
Implements Supply-Chain Firewall's `audit` subcommand.
"""

from argparse import Namespace
import logging

import scfw.package_managers as package_managers
from scfw.report import VerificationReport
from scfw.verifier import FindingSeverity
from scfw.verifiers import FirewallVerifiers

_log = logging.getLogger(__name__)


def run_audit(args: Namespace) -> int:
    """
    Audit installed packages using Supply-Chain Firewall's verifiers.

    Args:
        args: A `Namespace` containing the parsed `audit` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    try:
        package_manager = package_managers.get_package_manager(args.package_manager, executable=args.executable)

        packages = package_manager.list_installed_packages()
        _log.info(f"Installed packages: [{', '.join(map(str, packages))}]")

        verifiers = FirewallVerifiers()
        _log.info(f"Using package verifiers: [{', '.join(verifiers.names())}]")

        reports = verifiers.verify_packages(packages)

        merged_report = VerificationReport()
        for severity in FindingSeverity:
            if (severity_report := reports.get(severity)):
                merged_report.extend(severity_report)

        if merged_report:
            print(merged_report)
        else:
            print("No issues found.")

        return 0

    except Exception as e:
        _log.error(e)
        return 1
