"""
Defines an installation target verifier that uses Datadog Security Research's
malicious software packages dataset.
"""

from typing import Optional

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

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

    def name(self) -> str:
        """
        Return the `DatadogMaliciousPackagesVerifier` name string.

        Returns:
            The class' constant name string: `"DatadogMaliciousPackagesVerifier"`.
        """
        return "DatadogMaliciousPackagesVerifier"

    def verify(self, target: InstallTarget) -> Optional[str]:
        """
        Determine whether the given installation target is malicious by consulting
        the dataset's manifests.

        Args:
            target: The installation target to verify.

        Returns:
            A `str` stating that the installation target is malicious in the case
            that it exists in the dataset (otherwise `None`).
        """
        match target.ecosystem:
            case ECOSYSTEM.PIP:
                manifest = self._pypi_manifest
            case ECOSYSTEM.NPM:
                manifest = self._npm_manifest

        # We take the more conservative approach of ignoring version numbers when
        # deciding whether the given target is malicious
        if target.package in manifest:
            return (
                f"Datadog Security Research has determined that package {target.package} is malicious"
            )
        else:
            return None
