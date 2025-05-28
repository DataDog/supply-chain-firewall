"""
Provides a base class for representing supported package managers.
"""

from abc import (ABCMeta, abstractmethod)
from typing import Optional

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package


class PackageManager(metaclass=ABCMeta):
    """
    Abstract base class for representing supported package managers.
    """
    @abstractmethod
    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `PackageManager`.

        Args:
            executable:
                An optional local filesystem path to the underlying package manager executable
                that should be used for running commands. If none is provided, the executable
                is determined by the current environment.

        Raises:
            UnsupportedVersionError:
                Implementors should raise this error when the underlying executable has an
                unsupported version.
        """
        pass

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the name of the package manager, the standard fixed token by which
        it is invoked on the command line.
        """
        pass

    @classmethod
    @abstractmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the fixed package ecosystem the package manager is for.
        """
        pass

    @abstractmethod
    def executable(self) -> str:
        """
        Return the local filesystem path to the package manager executable.
        """
        pass

    @abstractmethod
    def run_command(self, command: list[str]):
        """
        Run the given package manager command.

        Args:
            command: The package manager command to be run.
        """
        pass

    @abstractmethod
    def resolve_install_targets(self, command: list[str]) -> list[Package]:
        """
        Resolve the package targets that would be installed if the given package
        manager command were run (without running it).

        Args:
            command: The package manager command whose installation targets are to be resolved.

        Returns:
            A `list[Package]` representing the package targets that would be installed
            if `command` were run.
        """
        pass

    @abstractmethod
    def list_installed_packages(self) -> list[Package]:
        """
        List all installed packages.

        Returns:
            A `list[Package]` representing all currently installed packages.
        """
        pass


class UnsupportedVersionError(Exception):
    """
    An exception that occurs when an attempt is made to initialize a `PackageManager`
    with an unsupported version of the underlying executable. Supply-Chain Firewall
    handles this exception gracefully, emitting an error log that states what occurred
    along with any error message attached to the `UnsupportedVersionError` exception.
    """
    pass
