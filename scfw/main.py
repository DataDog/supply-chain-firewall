"""
Provides the supply-chain firewall's main routine.
"""

import scfw.cli as cli
import scfw.firewall as firewall


def main() -> int:
    """
    The supply-chain firewall's main routine.

    Returns:
        An integer status code, 0 or 1.
    """
    args, help = cli.parse_command_line()

    if not args or args.subcommand != "run":
        print(help)
        return 0

    return firewall.run_firewall(args, help)
