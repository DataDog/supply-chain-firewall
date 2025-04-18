"""
Provides an interface for obtaining `PackageManagerCommand` instances from given
command lines for supported package managers.
"""

from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.commands.npm_command import NpmCommand
from scfw.commands.pip_command import PipCommand
from scfw.commands.poetry_command import PoetryCommand

SUPPORTED_PACKAGE_MANAGERS = {
    NpmCommand.name(),
    PipCommand.name(),
    PoetryCommand.name(),
}
"""
Contains the command line names of currently supported package managers.
"""


def get_package_manager_command(command: list[str], executable: Optional[str] = None) -> PackageManagerCommand:
    """
    Return a `PackageManagerCommand` for the given ecosystem and arguments.

    Args:
        command: The command line of the desired command as provided to the supply-chain firewall.
        executable: An optional executable to use when running the package manager command.

    Returns:
        A `PackageManagerCommand` initialized from the received command line.

    Raises:
        ValueError: An empty or unsupported package manager command line was provided.
    """
    if not command:
        raise ValueError("Missing package manager command")

    if command[0] == NpmCommand.name():
        return NpmCommand(command, executable)
    if command[0] == PipCommand.name():
        return PipCommand(command, executable)
    if command[0] == PoetryCommand.name():
        return PoetryCommand(command, executable)

    raise ValueError(f"Unsupported package manager '{command[0]}'")
