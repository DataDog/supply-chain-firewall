from scfw.ecosystem import ECOSYSTEM
from scfw.resolver import InstallTargetsResolver
from scfw.resolvers.npm_resolver import NpmInstallTargetsResolver
from scfw.resolvers.pip_resolver import PipInstallTargetsResolver


def get_install_targets_resolver(ecosystem: str) -> InstallTargetsResolver:
     match ecosystem:
        case ECOSYSTEM.PIP.value:
            return PipInstallTargetsResolver()
        case ECOSYSTEM.NPM.value:
            return NpmInstallTargetsResolver()
        case _:
            raise Exception(f"Unsupported ecosystem '{ecosystem}'")
