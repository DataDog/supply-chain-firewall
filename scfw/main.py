"""
Provides the supply-chain firewall's main routine.
"""

import logging
import time

import scfw.cli as cli
from scfw.cli import Subcommand
import scfw.configure as configure
import scfw.firewall as firewall

_log = logging.getLogger(__name__)


def main() -> int:
    """
    The supply-chain firewall's main routine.

    Returns:
        An integer status code, 0 or 1.
    """
    args, help = cli.parse_command_line()

    if not args:
        print(help, end='')
        return 0

    _configure_logging(args.log_level)

    _log.info(f"Starting Supply-Chain Firewall on {time.asctime(time.localtime())}")
    _log.debug(f"Command line: {vars(args)}")

    match Subcommand(args.subcommand):
        case Subcommand.Configure:
            return configure.run_configure(args)
        case Subcommand.Run:
            return firewall.run_firewall(args)

    return 0


def _configure_logging(level: int):
    """
    Configure the root logger.

    Args:
        level: The log level selected by the user.
    """
    handler = logging.StreamHandler()
    handler.addFilter(logging.Filter(name="scfw"))
    handler.setFormatter(logging.Formatter("[SCFW] %(levelname)s: %(message)s"))

    log = logging.getLogger()
    log.addHandler(handler)
    log.setLevel(level)
