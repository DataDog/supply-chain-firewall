"""
Entry point for module invocation via `python -m`.
"""

import sys

from scfw.firewall import run_firewall


if __name__ == "__main__":
    sys.exit(run_firewall())
