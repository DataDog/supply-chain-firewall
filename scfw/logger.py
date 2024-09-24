"""
Lorem ipsum dolor sic amet.
"""

from abc import (ABCMeta, abstractmethod)
from enum import Enum

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class FirewallAction(Enum):
    """
    Lorem ipsum dolor sic amet.
    """
    Allow = 0
    Block = 1
    Abort = 2


class FirewallLogger(metaclass=ABCMeta):
    """
    Lorem ipsum dolor sic amet.
    """
    @abstractmethod
    def log(
        self,
        action: FirewallAction,
        ecosystem: ECOSYSTEM,
        command: list[str],
        targets: list[InstallTarget]
    ):
        """
        Lorem ipsum dolor sic amet.
        """
        pass
