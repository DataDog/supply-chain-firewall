from dataclasses import dataclass

from scfw.ecosystem import ECOSYSTEM


@dataclass(eq=True, frozen=True)
class InstallTarget:
    """
    An installation target in a particular ecosystem.
    """
    ecosystem: ECOSYSTEM
    package: str
    version: str

    def show(self) -> str:
        """
        Format the `InstallTarget` package and version number as a string
        according to the conventions of its ecosystem.

        Args:
            self: The `InstallTarget` whose data is to be formatted.

        Returns:
            A `str` describing the `InstallTarget`'s package and version number
        """
        match self.ecosystem:
            case ECOSYSTEM.PIP:
                return f"{self.package}-{self.version}"
            case ECOSYSTEM.NPM:
                return f"{self.package}@{self.version}"
