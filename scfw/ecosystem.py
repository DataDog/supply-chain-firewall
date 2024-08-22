from enum import Enum


class ECOSYSTEM(Enum):
    """
    The package ecosystems currently supported by the supply-chain firewall.
    """
    PIP = "pip"
    NPM = "npm"
