from scfw.command import PackageManagerCommand
from scfw.commands.npm_command import NpmCommand
from scfw.commands.pip_command import PipCommand
from scfw.ecosystem import ECOSYSTEM


def get_package_manager_command(ecosystem: ECOSYSTEM, command: list[str]) -> PackageManagerCommand:
    match ecosystem:
        case ECOSYSTEM.PIP:
            return PipCommand(command)
        case ECOSYSTEM.NPM:
            return NpmCommand(command)
