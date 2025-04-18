"""
Defines a subclass of `PackageManagerCommand` for `poetry` commands.
"""

from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class PoetryCommand(PackageManagerCommand):
    """
    A representation of `poetry` commands via the `PackageManagerCommand` interface.
    """
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new `PoetryCommand`.

        Args:
            command: A `poetry` command line.
            executable:
                Optional path to the executable to run the command.  Determined by the
                environment if not given.

        Raises:
            ValueError: An invalid `poetry` command line was given.
            UnsupportedVersionError:
                An unsupported version of `poetry` was used to initialize a `PoetryCommand`.
        """
        pass

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `poetry` on the command line.
        """
        return "poetry"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the package ecosystem of `poetry` commands.
        """
        return ECOSYSTEM.PyPI

    def executable(self) -> str:
        """
        Query the executable for a `poetry` command.
        """
        return "poetry"

    def run(self):
        """
        Run a `poetry` command.
        """
        pass

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the package release targets a `poetry` command would install if
        it were run.

        Returns:
            A `list[InstallTarget]` representing the packages release targets the
            `poetry` command would install if it were run.
        """
        return []
