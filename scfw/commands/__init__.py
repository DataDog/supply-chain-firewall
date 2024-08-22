from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.commands.npm_command import NpmCommand
from scfw.commands.pip_command import PipCommand
from scfw.ecosystem import ECOSYSTEM


def get_package_manager_command(
    ecosystem: ECOSYSTEM,
    command: list[str],
    executable: Optional[str] = None
) -> PackageManagerCommand:
    """
    Return a `PackageManagerCommand` for the given ecosystem and arguments.

    Args:
        ecosystem: The ecosystem of the desired command.
        command: The command line of the desired command as provided to the supply-chain firewall.
        executable: An optional executable to use when running the package manager command.

    Returns:
        A `PackageManagerCommand` initialized from the given args in the desired ecosystem.
    """
    match ecosystem:
        case ECOSYSTEM.PIP:
            return PipCommand(command, executable)
        case ECOSYSTEM.NPM:
            return NpmCommand(command, executable)
