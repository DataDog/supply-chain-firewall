from scfw.ecosystem import ECOSYSTEM
from scfw.resolver import InstallTargetsResolver
from scfw.resolvers.npm_resolver import NpmInstallTargetsResolver
from scfw.resolvers.pip_resolver import PipInstallTargetsResolver


def get_install_targets_resolver(ecosystem: ECOSYSTEM) -> InstallTargetsResolver:
     match ecosystem:
        case ECOSYSTEM.PIP:
            return PipInstallTargetsResolver()
        case ECOSYSTEM.NPM:
            return NpmInstallTargetsResolver()
