"""
A representation of package ecosystems supported by the supply-chain firewall.
"""

from enum import Enum


class ECOSYSTEM(Enum):
    """
    Package ecosystems supported by the supply-chain firewall.
    """
    Npm = "npm"
    PyPI = "PyPI"

    def __str__(self) -> str:
        """
        Format an `ECOSYSTEM` for printing.

        Returns:
            A `str` representing the given `ECOSYSTEM` suitable for printing.
        """
        return self.value
