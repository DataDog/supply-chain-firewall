"""
Provides a base class for package verifiers.
"""

from abc import (ABCMeta, abstractmethod)
from enum import Enum

from scfw.package import Package


class FindingSeverity(Enum):
    """
    A hierarchy of severity levels for package verifier findings.

    Package verifiers attach severity levels to their findings in order to direct
    Supply-Chain Firewall to take the correct action with respect to blocking or
    warning on a package manager command.

    A `CRITICAL` finding causes Supply-Chain Firewall to block. A `WARNING` finding
    prompts it to seek confirmation from the user before running the command.
    """
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"

    def __str__(self) -> str:
        """
        Format a `FindingSeverity` for printing.

        Returns:
            A `str` representing the given `FindingSeverity` suitable for printing.
        """
        return self.name


class PackageVerifier(metaclass=ABCMeta):
    """
    Abstract base class for package verifiers.

    Each package verifier should implement a service for verifying packages in all
    supported ecosystems against a single reputable source of data on vulnerable and
    malicious open source packages.
    """
    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the verifier's name.

        Returns:
            A constant, short, descriptive name `str` identifying the verifier.
        """
        pass

    @abstractmethod
    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Verify the given package.

        Args:
            package: The `Package` to verify.

        Returns:
            A `list[tuple[FindingSeverity, str]]` of all findings for the given package
            reported by the backing data source, each tagged with a severity level.

            Each `str` in this list should be a concise summary of a single finding and
            would ideally provide a link or handle to more information about that finding
            for the benefit of the user.
        """
        pass
