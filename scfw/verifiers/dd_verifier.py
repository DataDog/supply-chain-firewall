from typing import Optional

import requests

from ecosystem import ECOSYSTEM
from target import InstallTarget
from verifier import InstallTargetVerifier

DD_DATASET_ECOSYSTEMS = {ECOSYSTEM.PIP: "pypi", ECOSYSTEM.NPM: "npm"}

DD_DATASET_SAMPLES_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"


class DatadogMaliciousPackagesVerifier(InstallTargetVerifier):
    def verify(self, target: InstallTarget) -> Optional[str]:
        manifest_url = f"{DD_DATASET_SAMPLES_URL}/{DD_DATASET_ECOSYSTEMS[target.ecosystem]}/manifest.json"

        # TODO: Download both manifests once at initialization
        request = requests.get(manifest_url)
        request.raise_for_status()

        manifest = request.json()
        if target.package not in manifest:
            return None

        return f"Package {target.package} has been determined to be malicious by Datadog Security Research"
