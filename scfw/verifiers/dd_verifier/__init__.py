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
        self._manifests = {}

        cache_dir = None
        if (home_dir := os.getenv(SCFW_HOME_VAR)):
            cache_dir = Path(home_dir) / "dd_verifier"

        for ecosystem in self.supported_ecosystems():
            if cache_dir:
                self._manifests[ecosystem] = dataset.get_latest_manifest(cache_dir, ecosystem)
            else:
                _, self._manifests[ecosystem] = dataset.download_manifest(ecosystem)

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
