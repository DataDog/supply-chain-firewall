"""
Implements the supply-chain firewall's `uninstall` command.
"""

from argparse import Namespace


def run_uninstall(args: Namespace) -> int:
    """
    Remove all Supply-Chain Firewall configuration and uninstall the tool.

    Args:
        args: A `Namespace` containing the parsed `uninstall` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    return 0
