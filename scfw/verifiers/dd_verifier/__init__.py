"""
Defines a package verifier for Datadog Security Research's malicious packages dataset.
"""

import logging
import os
from pathlib import Path

from scfw.constants import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import Finding, FindingSeverity, PackageVerifier, UnverifiablePackage
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

    def verify(self, package: Package) -> set[Finding]:
        """
        Determine whether the given package is malicious by consulting the dataset's manifests.

        Args:
            package: The `Package` to verify.

        Returns:
            A `set[Package]` containing a single `CRITICAL` finding in the event that `package`
            is found to be in the dataset, otherwise an empty set.

        Raises:
            UnverifiablePackage:
                The given package is from an unsupported ecosystem or has a known artifact
                source other than the ecosystem's main registry.
        """
        manifest = self._manifests.get(package.ecosystem)
        if not manifest:
            raise UnverifiablePackage(f"Package ecosystem {package.ecosystem} is not supported")

        if package.source is not None and not package.has_registry_source():
            raise UnverifiablePackage(f"Cannot verify package with non-{package.ecosystem} registry source")
        if package.source is None:
            _log.warning(
                f"{self.name()}: Unknown source for package {package}: assuming {package.ecosystem} registry source"
            )

        if (
            package.name in manifest
            and (not manifest[package.name] or package.version in manifest[package.name])
        ):
            return {
                Finding(
                    self.name(),
                    FindingSeverity.CRITICAL,
                    f"Datadog Security Research has determined that package {package} is malicious",
                )
            }

        return set()


def load_verifier() -> PackageVerifier:
    """
    Export `DatadogMaliciousPackagesVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `DatadogMaliciousPackagesVerifier` for use in a run of Supply-Chain Firewall.
    """
    return DatadogMaliciousPackagesVerifier()
