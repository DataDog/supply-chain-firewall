"""
Provides the supply-chain firewall's main routine.
"""

import logging
import time

import scfw.cli as cli
import scfw.firewall as firewall


def main() -> int:
    """
    The supply-chain firewall's main routine.

    Returns:
        An integer status code, 0 or 1.
    """
    args, help = cli.parse_command_line()

    if not args:
        print(help)
        return 0

    log = _root_logger()
    log.setLevel(args.log_level)

    log.info(f"Starting supply-chain firewall on {time.asctime(time.localtime())}")
    log.debug(f"Command line: {vars(args)}")

    if args.subcommand == "run":
        return firewall.run_firewall(args, help)

    return 0


def _root_logger() -> logging.Logger:
    """
    Configure the root logger and return a handle to it.

    Returns:
        A handle to the configured root logger.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    log = logging.getLogger()
    log.addHandler(handler)

    return log
