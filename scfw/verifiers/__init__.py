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

import concurrent.futures as cf
import importlib
import itertools
import logging
import os
import pkgutil

from scfw.report import VerificationReport
from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity

_log = logging.getLogger(__name__)


class FirewallVerifiers:
    """
    Provides a simple interface to verifying installation targets against the set
    of currently discoverable verifiers.
    """
    def __init__(self):
        """
        Initialize a `FirewallVerifiers` from currently discoverable installation
        target verifiers.
        """
        self._verifiers = []

        for _, module, _ in pkgutil.iter_modules([os.path.dirname(__file__)]):
            try:
                verifier = importlib.import_module(f".{module}", package=__name__).load_verifier()
                self._verifiers.append(verifier)
            except ModuleNotFoundError:
                _log.warning(f"Failed to load module {module} while collecting installation target verifiers")
            except AttributeError:
                _log.warning(f"Module {module} does not export an installation target verifier")

    def names(self) -> list[str]:
        """
        Return the names of discovered installation target verifiers.
        """
        return [verifier.name() for verifier in self._verifiers]

    def verify_targets(self, targets: list[InstallTarget]) -> dict[FindingSeverity, VerificationReport]:
        """
        Verify a set of installation targets against all discovered verifiers.

        Args:
            targets: The set of installation targets to verify.

        Returns:
            A set of severity-ranked verification reports resulting from verifying `targets`
            against all discovered verifiers.
        """
        reports: dict[FindingSeverity, VerificationReport] = {}

        with cf.ThreadPoolExecutor() as executor:
            task_results = {
                executor.submit(lambda v, t: v.verify(t), verifier, target): (verifier.name(), target)
                for verifier, target in itertools.product(self._verifiers, targets)
            }
            for future in cf.as_completed(task_results):
                verifier, target = task_results[future]
                if (findings := future.result()):
                    _log.info(f"Verifier {verifier} had findings for target {target}")
                    for severity, finding in findings:
                        if severity not in reports:
                            reports[severity] = VerificationReport()
                        reports[severity].insert(target, finding)
                else:
                    _log.info(f"Verifier {verifier} had no findings for target {target}")

        _log.info("Verification of installation targets complete")
        return reports
