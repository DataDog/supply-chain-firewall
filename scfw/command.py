"""
Provides a base class for representing the commands of package managers like `pip` and `npm`.
"""

from abc import (ABCMeta, abstractmethod)
from typing import Optional

from scfw.ecosystem import ECOSYSTEM
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

        Raises:
            UnsupportedVersionError:
                Subclasses should raise this error when an attempt is made to initialize an
                instance with an unsupported version of the underlying package manager.
        """
        pass

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the name of the package manager, the fixed token by which it is invoked.
        """
        pass

    @classmethod
    @abstractmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the package ecosystem associated with a package manager command.
        """
        pass

    @abstractmethod
    def executable(self) -> str:
        """
        Query the local filesystem path to the executable that would be used to run the
        package manager command.

        Returns:
            The local filesystem path of the executable that would be used to run the
            package manager command in the current environment.
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
    An error that occurs when an attempt is made to initialize a `PackageManagerCommand`
    with an unsupported version of the underlying package manager.

    When this occurs, subclasses of `PackageManagerCommand` should raise
    `UnsupportedVersionError` in their `__init__()` methods.  It should not be possible
    to initialize a `PackageManagerCommand` with an unsupported version.  The error
    should contain a message to the user with instructions for how to upgrade their
    package manager to a supported version.

    When `UnsupportedVersionError` is raised, the firewall logs an error message stating
    that an unsupported version error occurred, logs the error message from the
    `PackageManagerCommand`, and exits gracefully.
    """
    pass
