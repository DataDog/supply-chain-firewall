"""
Defines the supply-chain firewall's command-line interface and performs argument parsing.
"""

from argparse import ArgumentParser, Namespace
import logging
import sys

from scfw.ecosystem import ECOSYSTEM

_LOG_LEVELS = list(
    map(
        logging.getLevelName,
        [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]
    )
)
_DEFAULT_LOG_LEVEL = logging.getLevelName(logging.WARNING)


def _cli() -> ArgumentParser:
    """
    Defines the command-line interface for the supply-chain firewall.

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
        help="Verify any installation targets but do not run the package manager command"
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=_LOG_LEVELS,
        default=_DEFAULT_LOG_LEVEL,
        metavar="LEVEL",
        help="Desired logging level (default: %(default)s, options: %(choices)s)"
    )

    parser.add_argument(
        "--executable",
        type=str,
        default=None,
        metavar="PATH",
        help="Python or npm executable to use for running commands (default: environmentally determined)"
    )

    parser.add_argument(
        "--verifiers",
        type=str,
        default=None,
        metavar="PATH",
        help="Directory from which installation target verifiers should be sourced (default: scfw/verifiers)"
    )

    parser.add_argument(
        "--loggers",
        type=str,
        default=None,
        metavar="PATH",
        help="Directory from which loggers should be sourced (default: scfw/loggers)"
    )

    return parser


def _parse_command_line(argv: list[str]) -> tuple[Namespace, str]:
    """
    Parse the supply-chain firewall's command line from a given argument vector.

    Args:
        argv: The argument vector to be parsed.

    Returns:
        A `tuple` of a `Namespace` object containing the results of parsing the given
        argument vector and a `str` help message for the caller's use in early exits.

        The returned `Namespace` contains the package manager command present in
        the given argument vector as a (possibly empty) `list[str]` under the `command`
        attribute.
    """
    hinge = len(argv)
    for ecosystem in ECOSYSTEM:
        try:
            hinge = min(hinge, argv.index(ecosystem.value))
        except ValueError:
            pass

    parser = _cli()
    args = parser.parse_args(argv[1:hinge])
    args_dict = vars(args)
    args_dict["command"] = argv[hinge:]

    return args, parser.format_help()


def parse_command_line() -> tuple[Namespace, str]:
    """
    Parse the supply-chain firewall's command line.

    Returns:
        A `tuple` of a `Namespace` object containing:
          1. The results of successfully parsing the firewall's command line and
          2. A `str` help message for the caller's use in early exits.

        The returned `Namespace` contains the package manager command provided to the
        firewall as a (possibly empty) `list[str]` under the `command` attribute.

        Parsing errors cause the program to print a usage message and exit early
        with exit code 2.  This function only returns if parsing was successful.
    """
    return _parse_command_line(sys.argv)
