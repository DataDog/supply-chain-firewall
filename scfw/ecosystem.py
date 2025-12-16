"""
A representation of package ecosystems supported by the supply-chain firewall.
"""

from enum import Enum
from typing_extensions import Self


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

    @classmethod
    def from_string(cls, s: str) -> Self:
        """
        Convert a string into an `ECOSYSTEM`.

        Args:
            s: The `str` to be converted.

        Returns:
            The `ECOSYSTEM` referred to by the given string.

        Raises:
            ValueError: The given string does not refer to a valid `ECOSYSTEM`.
        """
        mappings = {f"{ecosystem}".lower(): ecosystem for ecosystem in cls}

        try:
            return mappings[s.lower()]
        except KeyError:
            raise ValueError(f"Invalid package ecosystem: '{s}'")
