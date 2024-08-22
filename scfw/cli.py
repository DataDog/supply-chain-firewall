from argparse import ArgumentParser, Namespace
import sys
from typing import Optional

from scfw.ecosystem import ECOSYSTEM


def _cli() -> ArgumentParser:
    """
    Defines the command-line interface for the supply-chain firewall itself.

    Returns:
        An `argparse.ArgumentParser` that encodes the supply-chain firewall's command line.

        This parser only handles the firewall's optional arguments.  It cannot be used to parse
        the firewall's entire command line, as this contains a command for a supported ecosystem's
        package manager which would otherwise be parsed greedily (and incorrectly) by `argparse`.
    """
    parser = ArgumentParser(
        prog="scfw",
        usage="%(prog)s [options] COMMAND",
        description="A tool to prevent the installation of vulnerable or malicious pip and npm packages"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip installation step regardless of verification results"
    )

    parser.add_argument(
        "--executable",
        type=str,
        default=None,
        metavar="PATH",
        help="Python or npm executable to use for running commands (default: environmentally determined)"
    )

    return parser


def parse_command_line() -> tuple[Namespace, Optional[tuple[ECOSYSTEM, list[str]]]]:
    """
    Parse the supply-chain firewall's command line.

    Returns:
        A `tuple` of
            1. A `Namespace` containing the firewall's own parsed command-line options and
            2. An optional `tuple` of an `ECOSYSTEM` and a command in that ecosystem's package manager
            (`None` if no such command was found)
    """
    install_command = None

    hinge = 0
    while hinge < len(sys.argv):
        match sys.argv[hinge]:
            case ECOSYSTEM.PIP.value:
                install_command = (ECOSYSTEM.PIP, sys.argv[hinge:])
                break
            case ECOSYSTEM.NPM.value:
                install_command = (ECOSYSTEM.NPM, sys.argv[hinge:])
                break
            case _:
                hinge += 1
    
    firewall_args = _cli().parse_args(sys.argv[1:hinge])

    return firewall_args, install_command
