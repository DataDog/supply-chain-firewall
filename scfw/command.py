from abc import (ABCMeta, abstractmethod)

from scfw.target import InstallTarget


class PackageManagerCommand(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, command: list[str]):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def would_install(self) -> list[InstallTarget]:
        pass
