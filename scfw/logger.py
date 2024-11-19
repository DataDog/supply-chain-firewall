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
    ALLOW = "ALLOW"
    ABORT = "ABORT"
    BLOCK = "BLOCK"

    def __lt__(self, other) -> bool:
        """
        Compare two `FirewallAction` instances on the basis of their underlying numeric values.

        Args:
            self: The `FirewallAction` to be compared on the left-hand side
            other: The `FirewallAction` to be compared on the right-hand side

        Returns:
            A `bool` indicating whether `<` holds between the two given `FirewallAction`.

        Raises:
            TypeError: The other argument given was not a `FirewallAction`.
        """
        if self.__class__ is not other.__class__:
            raise TypeError(
                f"'<' not supported between instances of '{self.__class__}' and '{other.__class__}'"
            )

        match self.name, other.name:
            case "ALLOW", "ABORT":
                return True
            case "ALLOW", "BLOCK":
                return True
            case "ABORT", "BLOCK":
                return True
            case _:
                return False


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
