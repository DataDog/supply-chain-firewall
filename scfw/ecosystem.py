"""
A representation of package ecosystems supported by the supply-chain firewall.
"""

from enum import Enum


class ECOSYSTEM(Enum):
    """
    Package ecosystems supported by the supply-chain firewall.
    """
    PIP = "pip"
    NPM = "npm"
