from argparse import ArgumentParser, Namespace
import sys

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


def _parse_command_line(argv: list[str]) -> tuple[Namespace, str]:
    """
    Parse the supply-chain firewall's command line.

    Returns:
        A `tuple` of a `Namespace` object containing the parsed firewall command line and
        a `str` help message for the caller's use in early exits

        The returned `Namespace` contains the package manager command provided to the firewall
        as a `list[str]` under the `command` attribute. If no such command was found, this
        attribute contains `[]`.
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
    return _parse_command_line(sys.argv)
