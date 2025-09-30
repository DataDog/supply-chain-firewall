"""
Users of Supply-Chain Firewall may provide custom package verifiers representing
alternative sources of truth for the firewall to use. This module contains a template
for writing such a custom verifier.

Supply-Chain Firewall discovers verifiers at runtime via the following simple protocol.
The module implementing the custom verifier must contain a function with the following
name and signature:

```
def load_verifier() -> PackageVerifier
```

This `load_verifier` function should return an instance of the custom verifier
for Supply-Chain Firewall's use. The module may then be placed in the scfw/verifiers
directory for runtime import without further modifications. Make sure to reinstall
the `scfw` package after doing so.
"""

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier


class CustomPackageVerifier(PackageVerifier):
    @classmethod
    def name(cls) -> str:
        return "CustomPackageVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        return set()

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        return []


def load_verifier() -> PackageVerifier:
    return CustomPackageVerifier()
