from abc import (ABCMeta, abstractmethod)
from typing import Optional

from scfw.target import InstallTarget


class InstallTargetVerifier(metaclass=ABCMeta):
    """
    Abstract base class for installation target verifiers.

    Each installation target verifier should implement a service for verifying
    installation targets against a single reputable source of data on vulnerable
    and malicious open source packages in all supported ecosystems.
    """
    @abstractmethod
    def verify(self, target: InstallTarget) -> Optional[str]:
        """
        Verify the given installation target.

        Args:
            self: The `InstallTargetVerifier` to be used for verification
            target: The installation target to verify

        Returns:
            If the given installation target is neither vulnerable nor malicious,
            `None` must be returned.

            Otherwise, a string describing the finding for the target from the
            backing data source should be returned.
        """
        pass
