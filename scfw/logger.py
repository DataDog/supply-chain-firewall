"""
Provides an interface for client loggers to receive information about a
completed run of the supply-chain firewall.
"""

from abc import (ABCMeta, abstractmethod)
from enum import Enum

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class FirewallAction(Enum):
    """
    The various actions the firewall may take in response to inspecting a
    package manager command.
    """
    Allow = 0
    Block = 1
    Abort = 2


class FirewallLogger(metaclass=ABCMeta):
    """
    An interface for passing information about a completed firewall run to
    client loggers.
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
        Pass data from a completed run of the firewall to a logger.

        Args:
            action: The action taken by the firewall.
            ecosystem: The ecosystem of the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets:
                The installation targets relevant to firewall's action.

                In the case of a blocking action, `targets` contains the installation
                targets that caused the firewall to block.  In the case of an aborting
                action, `targets` contains the targets that prompted the firewall to
                warn the user and seek confirmation to proceed.
        """
        pass
