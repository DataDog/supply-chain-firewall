"""
Implements Supply-Chain Firewall's `audit` subcommand.
"""

from argparse import Namespace


def run_audit(args: Namespace) -> int:
    """
    Audit installed packages using Supply-Chain Firewall's verifiers.

    Args:
        args: A `Namespace` containing the parsed `audit` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    return 0
