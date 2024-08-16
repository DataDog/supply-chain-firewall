from typing import Optional

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

DD_DATASET_SAMPLES_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"


class DatadogMaliciousPackagesVerifier(InstallTargetVerifier):
    def __init__(self):
        def download_manifest(ecosystem: str) -> dict[str, list[str]]:
            manifest_url = f"{DD_DATASET_SAMPLES_URL}/{ecosystem}/manifest.json"
            request = requests.get(manifest_url)
            request.raise_for_status()

            return request.json()

        self.pypi_manifest = download_manifest("pypi")
        self.npm_manifest = download_manifest("npm")

    def verify(self, target: InstallTarget) -> Optional[str]:
        match target.ecosystem:
            case ECOSYSTEM.PIP:
                manifest = self.pypi_manifest
            case ECOSYSTEM.NPM:
                manifest = self.npm_manifest

        if target.package not in manifest:
            return None

        return f"Package {target.package} has been determined to be malicious by Datadog Security Research"
