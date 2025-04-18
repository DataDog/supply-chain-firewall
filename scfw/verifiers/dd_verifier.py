"""
Defines an installation target verifier that uses Datadog Security Research's
malicious software packages dataset.
"""

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity, InstallTargetVerifier

_DD_DATASET_SAMPLES_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"


class DatadogMaliciousPackagesVerifier(InstallTargetVerifier):
    """
    An `InstallTargetVerifier` for Datadog Security Research's malicious packages dataset.
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

    def verify(self, target: InstallTarget) -> list[tuple[FindingSeverity, str]]:
        """
        Determine whether the given installation target is malicious by consulting
        the dataset's manifests.

        Args:
            target: The installation target to verify.

        Returns:
            A list containing any findings for the given installation target, obtained
            by checking for its presence in the dataset's manifests.  Only a single
            `CRITICAL` finding to this effect is present in this case.
        """
        match target.ecosystem:
            case ECOSYSTEM.Npm:
                manifest = self._npm_manifest
            case ECOSYSTEM.PyPI:
                manifest = self._pypi_manifest

        # We take the more conservative approach of ignoring version numbers when
        # deciding whether the given target is malicious
        if target.package in manifest:
            return [
                (
                    FindingSeverity.CRITICAL,
                    f"Datadog Security Research has determined that package {target.package} is malicious"
                )
            ]
        else:
            return []


def load_verifier() -> InstallTargetVerifier:
    """
    Export `DatadogMaliciousPackagesVerifier` for discovery by the firewall.

    Returns:
        A `DatadogMaliciousPackagesVerifier` for use in a run of the supply chain firewall.
    """
    return DatadogMaliciousPackagesVerifier()
