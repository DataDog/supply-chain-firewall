"""
Implements the supply-chain firewall's `init` subcommand.
"""

from argparse import Namespace
from pathlib import Path
import time


def initialize(args: Namespace, help: str) -> int:
    """
    Configure the environment for use with the supply-chain firewall.

    This includes setting shell aliases so that all of one's `pip` or `npm` commands
    are passively run through the firewall and configuring Datadog logging.
    """
    with open(Path.home() / ".bashrc", 'a') as f:
        f.write(f'\n# Added by `scfw` on {time.asctime(time.localtime())}')
        f.write('\nalias pip="scfw run pip"')
        f.write('\nalias npm="scfw run npm"\n')

    return 0
