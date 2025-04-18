"""
Provides an interface for client loggers to receive information about a
completed run of the supply-chain firewall.
"""

from abc import (ABCMeta, abstractmethod)
from enum import Enum
from typing_extensions import Self

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class FirewallAction(Enum):
    """
    The various actions the firewall may take in response to inspecting a
    package manager command.
    """
    ALLOW = 0
    BLOCK = 1

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

        return self.value < other.value

    def __str__(self) -> str:
        """
        Format a `FirewallAction` for printing.

        Returns:
            A `str` representing the given `FirewallAction` suitable for printing.
        """
        return self.name

    @classmethod
    def from_string(cls, s: str) -> Self:
        """
        Convert a string into a `FirewallAction`.

        Args:
            s: The `str` to be converted.

        Returns:
            The `FirewallAction` referred to by the given string.

        Raises:
            ValueError: The given string does not refer to a valid `FirewallAction`.
        """
        mappings = {f"{action}".lower(): action for action in cls}
        if (action := mappings.get(s.lower())):
            return action
        raise ValueError(f"Invalid firewall action '{s}'")


class FirewallLogger(metaclass=ABCMeta):
    """
    An interface for passing information about a completed firewall run to
    client loggers.
    """
    @abstractmethod
    def log(
        self,
        ecosystem: ECOSYSTEM,
        executable: str,
        command: list[str],
        targets: list[InstallTarget],
        action: FirewallAction,
        warned: bool
    ):
        """
        Pass data from a completed run of the firewall to a logger.

        Args:
            ecosystem: The ecosystem of the inspected package manager command.
            executable: The executable used to execute the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets:
                The installation targets relevant to firewall's action.

                In the case of a blocking action, `targets` contains the installation
                targets that caused the firewall to block.  In the case of an aborting
                action, `targets` contains the targets that prompted the firewall to
                warn the user and seek confirmation to proceed.
            action: The action taken by the firewall.
            warned:
                Indicates whether the user was warned about findings for any installation
                targets and prompted for approval to proceed with `command`.
        """
        pass
