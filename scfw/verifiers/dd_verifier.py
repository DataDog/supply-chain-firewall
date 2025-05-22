"""
Defines a package verifier for Datadog Security Research's malicious packages dataset.
"""

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier

_DD_DATASET_SAMPLES_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"


class DatadogMaliciousPackagesVerifier(PackageVerifier):
    """
    A `PackageVerifier` for Datadog Security Research's malicious packages dataset.
    """
    def __init__(self):
        """
        Initialize a new `DatadogMaliciousPackagesVerifier`.

        Raises:
            requests.HTTPError: An error occurred while fetching a manifest file.
        """
        def download_manifest(ecosystem: str) -> dict[str, list[str]]:
            manifest_url = f"{_DD_DATASET_SAMPLES_URL}/{ecosystem}/manifest.json"
            request = requests.get(manifest_url, timeout=5)
            request.raise_for_status()
            return request.json()

        self._pypi_manifest = download_manifest("pypi")
        self._npm_manifest = download_manifest("npm")

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
