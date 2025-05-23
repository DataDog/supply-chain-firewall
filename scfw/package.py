"""
A representation of software packages in supported ecosystems.
"""

from dataclasses import dataclass

from scfw.ecosystem import ECOSYSTEM


@dataclass(eq=True, frozen=True)
class Package:
    """
    Specifies a software package in a supported ecosystem.

    Attributes:
        ecosystem: The package's ecosystem.
        name: The package's name.
        version: The package's version string.
    """
    ecosystem: ECOSYSTEM
    name: str
    version: str

    def __str__(self) -> str:
        """
        Represent a `Package` as a string using ecosystem-specific formatting.

        Returns:
            A `str` with ecosystem-specific formatting describing the `Package` name and version.

            `npm` packages: `"{name}@{version}"`.
            `PyPI` packages: `"{name}-{version}"`
        """
        match self.ecosystem:
            case ECOSYSTEM.Npm:
                return f"{self.name}@{self.version}"
            case ECOSYSTEM.PyPI:
                return f"{self.name}-{self.version}"
