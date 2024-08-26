from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.commands.npm_command import NpmCommand
from scfw.commands.pip_command import PipCommand
from scfw.ecosystem import ECOSYSTEM


def get_package_manager_command(command: list[str], executable: Optional[str] = None) -> PackageManagerCommand:
    """
    Return a `PackageManagerCommand` for the given ecosystem and arguments.

    Args:
        command: The command line of the desired command as provided to the supply-chain firewall.
        executable: An optional executable to use when running the package manager command.

    Returns:
        A `PackageManagerCommand` initialized from the given args in the desired ecosystem.
    """
    assert command, "Missing package manager command"
    match command[0]:
        case ECOSYSTEM.PIP.value:
            return PipCommand(command, executable)
        case ECOSYSTEM.NPM.value:
            return NpmCommand(command, executable)
        case other:
            raise Exception(f"Unsupported package manager '{other}'")
