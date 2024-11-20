"""
Defines the supply-chain firewall's command-line interface and performs argument parsing.
"""

from argparse import Namespace
import logging
import sys
from typing import Optional

from scfw.ecosystem import ECOSYSTEM
from scfw.parser import ArgumentError, ArgumentParser

_LOG_LEVELS = list(
    map(
        logging.getLevelName,
        [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]
    )
)
_DEFAULT_LOG_LEVEL = logging.getLevelName(logging.WARNING)


def _add_run_cli(parser: ArgumentParser) -> None:
    """
    Defines the command-line interface for the firewall's `run` subcommand.

    Args:
        parser: The `ArgumentParser` to which the `run` command line will be added.
    """
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify any installation targets but do not run the package manager command"
    )

    parser.add_argument(
        "--executable",
        type=str,
        default=None,
        metavar="PATH",
        help="Python or npm executable to use for running commands (default: environmentally determined)"
    )


def _cli() -> ArgumentParser:
    """
    Defines the command-line interface for the supply-chain firewall.

    Returns:
        A parser for the supply-chain firewall's command line.

        This parser only handles the firewall's own optional arguments and subcommands.
        It does not parse the package manager commands being run through the firewall.
    """
    parser = ArgumentParser(
        prog="scfw",
        exit_on_error=False,
        description="A tool for preventing the installation of malicious PyPI and npm packages."
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=_LOG_LEVELS,
        default=_DEFAULT_LOG_LEVEL,
        metavar="LEVEL",
        help="Desired logging level (default: %(default)s, options: %(choices)s)"
    )

    subparsers = parser.add_subparsers(dest="subcommand")

    run_parser = subparsers.add_parser(
        "run",
        usage="%(prog)s [options] COMMAND",
        exit_on_error=False,
        description="Run a package manager command through the supply-chain firewall."
    )
    _add_run_cli(run_parser)

    return parser


def _parse_command_line(argv: list[str]) -> tuple[Optional[Namespace], str]:
    """
    Parse the supply-chain firewall's command line from a given argument vector.

    Args:
        argv: The argument vector to be parsed.

    Returns:
        A `tuple` of a `Namespace` object containing the results of parsing the given
        argument vector and a `str` help message for the caller's use in early exits.
        In the case of a parsing failure, `None` is returned instead of a `Namespace`.

        On success, the returned `Namespace` contains the package manager command
        present in the given argument vector as a (possibly empty) `list[str]` under
        the `command` attribute.
    """
    hinge = len(argv)
    for ecosystem in ECOSYSTEM:
        try:
            hinge = min(hinge, argv.index(ecosystem.value))
        except ValueError:
            pass

    parser = _cli()
    help_msg = parser.format_help()

    try:
        args = parser.parse_args(argv[1:hinge])
        args_dict = vars(args)
        args_dict["command"] = argv[hinge:]
        return args, help_msg

    except ArgumentError:
        return None, help_msg


def parse_command_line() -> tuple[Optional[Namespace], str]:
    """
    Parse the supply-chain firewall's command line.

    Returns:
        A `tuple` of a `Namespace` object containing the results of parsing the
        firewall's command line and a `str` help message for the caller's use in
        early exits. In the case of a parsing failure, `None` is returned instead
        of a `Namespace`.

        On success, the returned `Namespace` contains the package manager command
        provided to the firewall as a (possibly empty) `list[str]` under the `command`
        attribute.
    """
    return _parse_command_line(sys.argv)
