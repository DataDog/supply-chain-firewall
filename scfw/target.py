from dataclasses import dataclass

from scfw.ecosystem import ECOSYSTEM


@dataclass(eq=True, frozen=True)
class InstallTarget:
    ecosystem: ECOSYSTEM
    package: str
    version: str

    def show(self) -> str:
        match self.ecosystem:
            case ECOSYSTEM.PIP:
                return f"{self.package}-{self.version}"
            case ECOSYSTEM.NPM:
                return f"{self.package}@{self.version}"
