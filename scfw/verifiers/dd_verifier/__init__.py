"""
Defines a package verifier for Datadog Security Research's malicious packages dataset.
"""

import logging
import os
from pathlib import Path

from scfw.constants import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
import scfw.verifiers.dd_verifier.dataset as dataset

_log = logging.getLogger(__name__)

DD_VERIFIER_HOME = Path("dd_verifier/")
"""
The `DatadogMaliciousPackagesVerifier` home directory, relative to `SCFW_HOME`.
"""


class DatadogMaliciousPackagesVerifier(PackageVerifier):
    """
    A `PackageVerifier` for Datadog Security Research's malicious packages dataset.
    """
    def __init__(self):
        """
        Initialize a new `DatadogMaliciousPackagesVerifier`.
        """
        self._manifests = {}

        cache_dir = None
        if (scfw_home := os.getenv(SCFW_HOME_VAR)):
            dd_verifier_home = Path(scfw_home) / DD_VERIFIER_HOME
            try:
                if not dd_verifier_home.is_dir():
                    dd_verifier_home.mkdir(parents=True)
                cache_dir = dd_verifier_home
            except Exception as e:
                _log.warning(
                    f"Failed to set up cache directory for Datadog malicious packages verifier: {e}"
                )

        for ecosystem in self.supported_ecosystems():
            if cache_dir:
                self._manifests[ecosystem] = dataset.get_latest_manifest(cache_dir, ecosystem)
            else:
                self._manifests[ecosystem] = dataset.download_manifest(ecosystem)

    @classmethod
    def name(cls) -> str:
        """
        Return the `DatadogMaliciousPackagesVerifier` name string.

        Returns:
            The class' constant name string: `"DatadogMaliciousPackagesVerifier"`.
        """
        return "DatadogMaliciousPackagesVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems supported by `DatadogMaliciousPackagesVerifier`.

        Returns:
            The class' constant set of supported ecosystems: `{ECOSYSTEM.Npm, ECOSYSTEM.PyPI}`.
        """
        return {ECOSYSTEM.Npm, ECOSYSTEM.PyPI}

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Determine whether the given package is malicious by consulting the dataset's manifests.

        Args:
            package: The `Package` to verify.

        Returns:
            A list containing any findings for the given package, obtained by checking for its
            presence in the dataset's manifests.  Only a single `CRITICAL` finding to this effect
            is present in this case.
        """
        manifest = self._manifests.get(package.ecosystem)
        if not manifest:
            return [(FindingSeverity.WARNING, f"Package ecosystem {package.ecosystem} is not supported")]

        if (
            package.name in manifest
            and (not manifest[package.name] or package.version in manifest[package.name])
        ):
            return [
                (
                    FindingSeverity.CRITICAL,
                    f"Datadog Security Research has determined that package {package} is malicious"
                )
            ]
        else:
            return []


def load_verifier() -> PackageVerifier:
    """
    Export `DatadogMaliciousPackagesVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `DatadogMaliciousPackagesVerifier` for use in a run of Supply-Chain Firewall.
    """
    return DatadogMaliciousPackagesVerifier()
