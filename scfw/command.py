from abc import (ABCMeta, abstractmethod)
from typing import Optional

from scfw.target import InstallTarget


class PackageManagerCommand(metaclass=ABCMeta):
    """
    Abstract base class for commands in an ecosystem's package manager.
    """
    @abstractmethod
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new package manager command.

        Args:
            self: The `PackageManagerCommand` to be initialized
            command: The package manager command line as provided to the supply-chain firewall.
            executable: An optional path to the executable to use to run the package manager
            commands. Must be determined from the environment if not provided.
        """
        pass

    @abstractmethod
    def run(self):
        """
        Run a package manager command.

        Args:
            self: The `PackageManagerCommand` whose underlying command line should be run.
        """
        pass

    @abstractmethod
    def would_install(self) -> list[InstallTarget]:
        """
        Without running the command, determine the packages that would be installed by a
        package manager command if it were run.

        Args:
            self: The `PackageManagerCommand` to inspect.

        Returns:
            A list of `InstallTarget` representing the installation targets the
            command would install or upgrade if it were run.
        """
        pass
