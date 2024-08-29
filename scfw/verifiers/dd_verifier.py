from typing import Optional

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

DD_DATASET_SAMPLES_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"


class DatadogMaliciousPackagesVerifier(InstallTargetVerifier):
    """
    An `InstallTargetVerifier` for Datadog's public malicious packages dataset.
    """
    def __init__(self):
        """
        Initialize a new `DatadogMaliciousPackagesVerifier`

        Args:
            self: The verifier to be initialized.
        """
        def download_manifest(ecosystem: str) -> dict[str, list[str]]:
            manifest_url = f"{DD_DATASET_SAMPLES_URL}/{ecosystem}/manifest.json"
            request = requests.get(manifest_url)
            request.raise_for_status()
            return request.json()

        self.pypi_manifest = download_manifest("pypi")
        self.npm_manifest = download_manifest("npm")

    def name(self) -> str:
        """
        Return the `DatadogMaliciousPackagesVerifier` name string.

        Args:
            self: The `DatadogMaliciousPackagesVerifier` whose name is requested.

        Returns:
            The class' constant name string.
        """
        return "DatadogMaliciousPackagesVerifier"

    def verify(self, target: InstallTarget) -> Optional[str]:
        """
        Determine whether the given installation target is malicious by consulting
        the dataset's manifests.

        Args:
            target: The installation target to verify.

        Returns:
            An indicator of whether samples of the target are present in the dataset.
        """
        match target.ecosystem:
            case ECOSYSTEM.PIP:
                manifest = self.pypi_manifest
            case ECOSYSTEM.NPM:
                manifest = self.npm_manifest

        # We take the more conservative approach of ignoring version numbers when
        # deciding whether the given target is malicious
        if target.package in manifest:
            return (
                f"Package {target.package} has been determined to be malicious by Datadog Security Research"
            )
        else:
            return None
