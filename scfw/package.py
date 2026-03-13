"""
A representation of software packages in supported ecosystems.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scfw.ecosystem import ECOSYSTEM


@dataclass(eq=True, frozen=True)
class LocalPackageSource:
    """
    Specifies a local source for a software package.

    Attributes:
        local_source: A `Path` to the local source for the package.
    """
    local_source: Path


@dataclass(eq=True, frozen=True)
class RemotePackageSource:
    """
    Specifies a remote source for a software package.

    Attributes:
        remote_source: A `str` specifying the remote source for the package (e.g., download URL).
    """
    remote_source: str


@dataclass(eq=True, frozen=True)
class Package:
    """
    Specifies a software package in a supported ecosystem.

    Attributes:
        ecosystem: The package's ecosystem.
        name: The package's name.
        version: The package's version string.
        source: Optional data specifying the package source (local or remote).
    """
    ecosystem: ECOSYSTEM
    name: str
    version: str
    source: Optional[LocalPackageSource | RemotePackageSource] = None

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

    def get_local_source(self) -> Optional[LocalPackageSource]:
        """
        Return the package's `source` if it is local.

        Returns:
            The package's `LocalPackageSource` attribute or `None` if the source
            is undefined or remote.
        """
        if isinstance(self.source, LocalPackageSource):
            return self.source

    def get_remote_source(self) -> Optional[RemotePackageSource]:
        """
        Return the package's `source` if it is remote.

        Returns:
            The package's `RemotePackageSource` attribute or `None` if the source
            is undefined or remote.
        """
        if isinstance(self.source, RemotePackageSource):
            return self.source
