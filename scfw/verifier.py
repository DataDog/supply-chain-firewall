from abc import (ABCMeta, abstractmethod)
from typing import Optional

from target import InstallTarget


class InstallTargetVerifier(metaclass=ABCMeta):
    @abstractmethod
    def verify(self, target: InstallTarget) -> Optional[str]:
        pass
