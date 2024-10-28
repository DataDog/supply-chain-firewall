"""
Users of the supply chain firewall may provide custom installation target
verifiers representing alternative sources of truth for the firewall to use.
This module contains a template for writing such a custom verifier.

The firewall discovers verifiers at runtime via the following simple protocol.
The module implementing the custom verifier must contain a function with the
following name and signature:

```
def load_verifier() -> InstallTargetVerifier
```

This `load_verifier` function should return an instance of the custom verifier
for the firewall's use. The module may then be placed in the scfw/verifiers directory
for runtime import, no further modification required.. Make sure to reinstall the
package after doing so.
"""

from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity, InstallTargetVerifier


class CustomInstallTargetVerifier(InstallTargetVerifier):
    def name(self) -> str:
        return "CustomInstallTargetVerifier"

    def verify(self, target: InstallTarget) -> list[tuple[FindingSeverity, str]]:
        return []


def load_verifier() -> InstallTargetVerifier:
    return CustomInstallTargetVerifier()
