"""
Provides an interface for obtaining `PackageManager` instances needed for runs
of Supply-Chain Firewall.
"""

from typing import Optional

from scfw.package_manager import PackageManager
from scfw.package_managers.npm import Npm
from scfw.package_managers.pip import Pip
from scfw.package_managers.poetry import Poetry

SUPPORTED_PACKAGE_MANAGERS = [
    Npm.name(),
    Pip.name(),
    Poetry.name(),
]
"""
Contains the command line names of supported package managers.
"""


def get_package_manager(name: str, executable: Optional[str] = None) -> PackageManager:
    """
    Return a `PackageManager` corresponding to the given command line name.

    Args:
        name: The command line name of the desired `PackageManager`.
        executable: An optional executable to use to initialize the returned `PackageManager`.

    Returns:
        A `PackageManager` corresponding to `name` and initialized from `executable`.

    Raises:
        ValueError: An empty or unsupported package manager name was provided.
    """
    if not name:
        raise ValueError("Missing package manager")

    if name == Npm.name():
        return Npm(executable)
    if name == Pip.name():
        return Pip(executable)
    if name == Poetry.name():
        return Poetry(executable)

    raise ValueError(f"Unsupported package manager '{name}'")
