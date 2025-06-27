"""
Defines a package verifier for Datadog Security Research's malicious packages dataset.
"""

import os
from pathlib import Path

from scfw.configure import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
import scfw.verifiers.dd_verifier.dataset as dataset


class DatadogMaliciousPackagesVerifier(PackageVerifier):
    """
    A `PackageVerifier` for Datadog Security Research's malicious packages dataset.
    """
    def __init__(self):
        """
        Initialize a new `DatadogMaliciousPackagesVerifier`.
        """
        if (home_dir := os.getenv(SCFW_HOME_VAR)):
            cache_dir = Path(home_dir) / "dd_verifier"
            self._npm_manifest = dataset.get_latest_manifest(cache_dir, ECOSYSTEM.Npm)
            self._pypi_manifest = dataset.get_latest_manifest(cache_dir, ECOSYSTEM.PyPI)
        else:
            _, self._npm_manifest = dataset.download_manifest(ECOSYSTEM.Npm)
            _, self._pypi_manifest = dataset.download_manifest(ECOSYSTEM.PyPI)

    @classmethod
    def name(cls) -> str:
        """
        Return the `DatadogMaliciousPackagesVerifier` name string.

        Returns:
            The class' constant name string: `"DatadogMaliciousPackagesVerifier"`.
        """
        return "DatadogMaliciousPackagesVerifier"

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
        match package.ecosystem:
            case ECOSYSTEM.Npm:
                manifest = self._npm_manifest
            case ECOSYSTEM.PyPI:
                manifest = self._pypi_manifest

        # We take the more conservative approach of ignoring version strings when
        # deciding whether the given package is malicious
        if package.name in manifest:
            return [
                (
                    FindingSeverity.CRITICAL,
                    f"Datadog Security Research has determined that package {package.name} is malicious"
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
