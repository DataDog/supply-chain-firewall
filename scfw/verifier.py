"""
Provides a base class for installation target verifiers.
"""

from abc import (ABCMeta, abstractmethod)
from typing import Optional

from scfw.target import InstallTarget


class InstallTargetVerifier(metaclass=ABCMeta):
    """
    Abstract base class for installation target verifiers.

    Each installation target verifier should implement a service for verifying
    installation targets in all supported ecosystems against a single reputable
    source of data on vulnerable and malicious open source packages.
    """
    @abstractmethod
    def name(self) -> str:
        """
        Return the verifier's name.

        Returns:
            A constant, short, descriptive name `str` identifying the verifier.
        """
        pass

    @abstractmethod
    def verify(self, target: InstallTarget) -> Optional[str]:
        """
        Verify the given installation target.

        Args:
            target: The installation target to verify.

        Returns:
            In the case that the target is considered vulnerable or malicious
            by the backing data source, a `str` should be returned stating
            this and (as much as possible) describing why.  Otherwise, `None`
            should be returned.
        """
        pass
