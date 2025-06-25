"""
Defines a package verifier for Datadog Security Research's malicious packages dataset.
"""

import json
import os
from pathlib import Path
import requests
from typing import Optional

from scfw.configure import SCFW_HOME_VAR
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
            RuntimeError: Failed to download the dataset from GitHub and no cached copy is available.
        """
        def get_manifest(cache_dir: Optional[Path], ecosystem: ECOSYSTEM) -> dict[str, list[str]]:
            cached_manifest_file = cache_dir / f"{ecosystem}_manifest.json" if cache_dir else None

            try:
                manifest_url = f"{_DD_DATASET_SAMPLES_URL}/{str(ecosystem).lower()}/manifest.json"
                request = requests.get(manifest_url, timeout=5)
                request.raise_for_status()

                # Update the cached manifest file
                if cached_manifest_file:
                    if not cached_manifest_file.parent.is_dir():
                        cached_manifest_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(cached_manifest_file, 'w') as f:
                        f.write(request.text)

                return request.json()

            except requests.HTTPError:
                if not cached_manifest_file or not cached_manifest_file.is_file():
                    raise RuntimeError(f"Failed to download {ecosystem} dataset and no local copy available")

                with open(cached_manifest_file) as f:
                    return json.loads(f.read())

        home_dir = os.getenv(SCFW_HOME_VAR)
        cache_dir = Path(home_dir) / "dd_verifier" if home_dir else None

        self._npm_manifest = get_manifest(cache_dir, ECOSYSTEM.Npm)
        self._pypi_manifest = get_manifest(cache_dir, ECOSYSTEM.PyPI)

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
