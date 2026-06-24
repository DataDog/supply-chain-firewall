"""
Provides a base class for package verifiers.
"""

from abc import (ABCMeta, abstractmethod)
from dataclasses import dataclass
from enum import Enum
from typing_extensions import Self

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package


class FindingSeverity(Enum):
    """
    A hierarchy of severity levels for package verifier findings.

    Package verifiers attach severity levels to their findings in order to direct
    Supply Chain Firewall to take the correct action with respect to blocking or
    warning on a package manager command.

    A `CRITICAL` finding causes Supply Chain Firewall to block. A `WARNING` finding
    prompts it to seek confirmation from the user before running the command.
    """
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"

    def __lt__(self, other) -> bool:
        """
        Compare two `FindingSeverity` instances on the basis of their severity ranking.

        Args:
            self: The `FindingSeverity` to be compared on the left-hand side
            other: The `FindingSeverity` to be compared on the right-hand side

        Returns:
            A `bool` indicating whether `<` holds between the two given `FindingSeverity`.

        Raises:
            TypeError: The other argument given was not a `FindingSeverity`.
        """
        if self.__class__ is not other.__class__:
            raise TypeError(
                f"'<' not supported between instances of '{self.__class__}' and '{other.__class__}'"
            )

        return self == FindingSeverity.WARNING and other == FindingSeverity.CRITICAL

    def __str__(self) -> str:
        """
        Format a `FindingSeverity` for printing.

        Returns:
            A `str` representing the given `FindingSeverity` suitable for printing.
        """
        return self.name

    @classmethod
    def from_string(cls, s: str) -> Self:
        """
        Convert a string into a `FindingSeverity`.

        Args:
            s: The `str` to be converted.

        Returns:
            The `FindingSeverity` referred to by the given string.

        Raises:
            ValueError: The given string does not refer to a valid `FindingSeverity`.
        """
        mappings = {f"{severity}".lower(): severity for severity in cls}

        try:
            return mappings[s.lower()]
        except KeyError:
            raise ValueError(f"Invalid finding severity: '{s}'")


@dataclass(eq=True, frozen=True)
class Finding:
    """
    A finding reported by a verifier with an accompanying severity assessment.
    """
    verifier: str
    severity: FindingSeverity
    finding: str


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

    @classmethod
    @abstractmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems the verifier supports.

        Returns:
            A constant `set` of `ECOSYSTEM` representing the package ecosystems
            supported for verification by the verifier.
        """
        pass

    @abstractmethod
    def verify(self, package: Package) -> set[Finding]:
        """
        Verify the given package.

        Args:
            package: The `Package` to verify.

        Returns:
            A `set[Finding]` of all findings reported for the given package.

            The text of each finding should be concise and would ideally link to or
            reference other sources of information for the benefit of the user.
        """
        pass


class UnverifiablePackage(Exception):
    """
    An exception that occurs when a verifier is unable to verify a given package.
    This is to be distinguished from a verification failure, i.e., when errors occur
    in the course of verifying a package.

    The canonical use-case for this exception occurs when a package is not within the
    purview of a verifier's backing data source. For instance, a package sourced from
    a private package registry would not be within the purview of a verifier that only
    covers packages sourced from an ecosystem's main public registry.

    Supply Chain Firewall handles this exception gracefully by separately collecting,
    logging and reporting any packages that were unable to be verified.
    """
    pass
