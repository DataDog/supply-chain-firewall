from abc import (ABCMeta, abstractmethod)
from typing import Optional

from scfw.target import InstallTarget


class PackageManagerCommand(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, command: list[str], executable: Optional[str] = None):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def would_install(self) -> list[InstallTarget]:
        pass
