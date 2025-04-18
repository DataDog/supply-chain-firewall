"""
A representation of package manager installation targets in a supported ecosystem.
"""

from dataclasses import dataclass

from scfw.ecosystem import ECOSYSTEM


@dataclass(eq=True, frozen=True)
class InstallTarget:
    """
    An installation target in a particular ecosystem.

    Attributes:
        ecosystem: The ecosystem of the installation target.
        package: The installation target's package name in its ecosystem.
        version: The installation target's version number.
    """
    ecosystem: ECOSYSTEM
    package: str
    version: str

    def __str__(self) -> str:
        """
        Format the `InstallTarget` package and version number as a string according
        to the conventions of its ecosystem.

        Returns:
            A `str` with ecosystem-specific formatting describing the `InstallTarget`
            package and version number.

            For `pip` packages, the formatting used is `"{package}-{version}"` and for `npm`
            packages it is `"{package}@{version}"`.
        """
        match self.ecosystem:
            case ECOSYSTEM.Npm:
                return f"{self.package}@{self.version}"
            case ECOSYSTEM.PyPI:
                return f"{self.package}-{self.version}"
