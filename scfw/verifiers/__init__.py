"""
Exports the currently discoverable set of installation target verifiers
for use in the supply chain firewall's main routine.

Two installation target verifiers ship with the supply chain firewall
by default: one that uses Datadog Security Research's public malicious
packages dataset and one that uses OSV.dev. Users of the supply chain
firewall may additionally provide custom verifiers representing alternative
sources of truth for the firewall to use.

The firewall discovers verifiers at runtime via the following simple protocol.
The module implementing the custom verifier must contain a function with the
following name and signature:

```
def load_verifier() -> InstallTargetVerifier
```

This `load_verifier` function should return an instance of the custom verifier
for the firewall's use. The module may then be placed in the same directory
as this source file for runtime import. Make sure to reinstall the package
after doing so.
"""

import importlib
import logging
import os
import pkgutil

from scfw.verifier import InstallTargetVerifier

_log = logging.getLogger(__name__)


def get_install_target_verifiers() -> list[InstallTargetVerifier]:
    """
    Return the currently discoverable set of installation target verifiers.

    Returns:
        A list of the discovered installation target verifiers.
    """
    verifiers = []

    for _, module, _ in pkgutil.iter_modules([os.path.dirname(__file__)]):
        try:
            verifier = importlib.import_module(f".{module}", package=__name__).load_verifier()
            verifiers.append(verifier)
        except ModuleNotFoundError:
            _log.warning(f"Failed to load module {module} while collecting installation target verifiers")
        except AttributeError:
            _log.warning(f"Module {module} does not export an installation target verifier")

    return verifiers
