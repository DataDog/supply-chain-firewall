"""
Exports the currently discoverable set of package verifiers for use in
Supply-Chain Firewall.

Two package verifiers ship with Supply-Chain Firewall by default: one for
Datadog Security Research's malicious packages dataset and one for OSV.dev's
advisory database. Users of Supply-Chain Firewall may additionally provide
custom verifiers representing alternative sources of truth.

Supply-Chain Firewall discovers verifiers at runtime via the following protocol.
The module implementing the custom verifier must contain a function with the
following name and signature:

```
def load_verifier() -> PackageVerifier
```

This `load_verifier` function should return an instance of the custom verifier.
The module may then be placed in the same directory as this source file for
runtime import. Make sure to reinstall Supply-Chain Firewall after doing so.
"""

import concurrent.futures as cf
import importlib
import itertools
import logging
import os
import pkgutil

from scfw.package import Package
from scfw.report import VerificationReport
from scfw.verifier import FindingSeverity

_log = logging.getLogger(__name__)


class FirewallVerifiers:
    """
    Provides a simple interface to verifying packages against the set of currently
    discoverable verifiers.
    """
    def __init__(self):
        """
        Initialize a `FirewallVerifiers` from currently discoverable package verifiers.
        """
        self._verifiers = []

        for _, module, _ in pkgutil.iter_modules([os.path.dirname(__file__)]):
            try:
                verifier = importlib.import_module(f".{module}", package=__name__).load_verifier()
                self._verifiers.append(verifier)
            except ModuleNotFoundError:
                _log.warning(f"Failed to load module {module} while collecting package verifiers")
            except AttributeError:
                _log.warning(f"Module {module} does not export a package verifier")

    def names(self) -> list[str]:
        """
        Return the names of discovered package verifiers.
        """
        return [verifier.name() for verifier in self._verifiers]

    def verify_packages(self, packages: list[Package]) -> dict[FindingSeverity, VerificationReport]:
        """
        Verify a set of packages against all discovered verifiers.

        Args:
            packages: The set of `Package` to verify.

        Returns:
            A set of severity-ranked verification reports resulting from verifying
            `packages` against all discovered verifiers.
        """
        reports: dict[FindingSeverity, VerificationReport] = {}

        with cf.ThreadPoolExecutor() as executor:
            task_results = {
                executor.submit(lambda v, t: v.verify(t), verifier, package): (verifier.name(), package)
                for verifier, package in itertools.product(self._verifiers, packages)
            }
            for future in cf.as_completed(task_results):
                verifier, package = task_results[future]
                if (findings := future.result()):
                    _log.info(f"Verifier {verifier} had findings for package {package}")
                    for severity, finding in findings:
                        if severity not in reports:
                            reports[severity] = VerificationReport()
                        reports[severity].insert(package, finding)
                else:
                    _log.info(f"Verifier {verifier} had no findings for package {package}")

        _log.info("Verification of packages complete")
        return reports
