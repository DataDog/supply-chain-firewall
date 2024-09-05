"""
Provides a base class for representing the commands of package managers like `pip` and `npm`.
"""

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
            command: The package manager command line as provided to the supply-chain firewall.
            executable:
                Optional path to the executable to run the command.  Determined by the environment
                where the firewall is running if not given.

        Raises
            UnsupportedVersionError:
                Subclasses should raise this error when an attempt is made to use an unsupported
                version of the package manager to execute commands, in particular the commands
                that must be run in order to implement the `would_install()` method.
        """
        pass

    @abstractmethod
    def run(self):
        """
        Run a package manager command.
        """
        pass

    @abstractmethod
    def would_install(self) -> list[InstallTarget]:
        """
        Without running the command, determine the packages that would be installed by a
        package manager command if it were run.

        Returns:
            A list of `InstallTarget` representing the installation targets the command would
            install or upgrade if it were run.
        """
        pass


class UnsupportedVersionError(Exception):
    """
    An error that occurs when an attempt is made to use an unsupported version of a package
    manager with a `PackageManagerCommand`.

    Subclasses of `PackageManagerCommand` should raise `UnsupportedVersionError` when this
    occurs.  In this case, the firewall will log the error message and exit gracefully
    instead of crashing.
    """
    pass
