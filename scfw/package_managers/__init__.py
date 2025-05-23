"""
Provides an interface for obtaining `PackageManager` instances needed for runs
of Supply-Chain Firewall.
"""

from typing import Optional

from scfw.package_manager import PackageManager
from scfw.package_managers.npm import Npm
from scfw.package_managers.pip import Pip
from scfw.package_managers.poetry import Poetry

SUPPORTED_PACKAGE_MANAGERS = {
    Npm.name(),
    Pip.name(),
    Poetry.name(),
}
"""
Contains the command line names of supported package managers.
"""


def get_package_manager(command: list[str], executable: Optional[str] = None) -> PackageManager:
    """
    Return a `PackageManager` corresponding to the given command line.

    Args:
        command: The command line of the desired command as provided to Supply-Chain Firewall.
        executable: An optional executable to use to initialize the returned `PackageManager`.

    Returns:
        A `PackageManager` corresponding to `command` and initialized from `executable`.

    Raises:
        ValueError: An empty or unsupported package manager command line was provided.
    """
    if not command:
        raise ValueError("Missing package manager command")

    if command[0] == Npm.name():
        return Npm(executable)
    if command[0] == Pip.name():
        return Pip(executable)
    if command[0] == Poetry.name():
        return Poetry(executable)

    raise ValueError(f"Unsupported package manager '{command[0]}'")
