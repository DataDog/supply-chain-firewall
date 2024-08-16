from dataclasses import dataclass

from scfw.ecosystem import ECOSYSTEM


@dataclass
class InstallTarget:
    ecosystem: ECOSYSTEM
    package: str
    version: str

    def show(self) -> str:
        return f"{self.ecosystem.value}|{self.package}:{self.version}"
