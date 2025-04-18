"""
Provides a base class for installation target verifiers.
"""

from abc import (ABCMeta, abstractmethod)
from enum import Enum

from scfw.target import InstallTarget


class FindingSeverity(Enum):
    """
    A hierarchy of severity levels for installation target verifier findings.

    Installation target verifiers attach severity levels to their findings in
    order to direct the supply-chain firewall to take the correct action with
    respect to blocking or warning on an installation request.

    A `CRITICAL` finding causes the supply-chain firewall to block. A `WARNING`
    finding prompts the firewall to seek confirmation from the user before
    proceeding with the installation request.
    """
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"


class InstallTargetVerifier(metaclass=ABCMeta):
    """
    Abstract base class for installation target verifiers.

    Each installation target verifier should implement a service for verifying
    installation targets in all supported ecosystems against a single reputable
    source of data on vulnerable and malicious open source packages.
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
    def verify(self, target: InstallTarget) -> list[tuple[FindingSeverity, str]]:
        """
        Verify the given installation target.

        Args:
            target: The installation target to verify.

        Returns:
            A `list[tuple[FindingSeverity, str]]` of all findings for the given
            installation target reported by the backing data source, each tagged
            with a severity level for the firewall's use.

            Each `str` in this list should be a concise summary of a single finding
            and would ideally provide a link or handle to more information about that
            finding for the benefit of the user.
        """
        pass
