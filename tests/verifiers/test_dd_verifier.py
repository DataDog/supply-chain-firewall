"""
Tests of `DatadogMaliciousPackagesVerifier`.
"""

import glob
import json
from pathlib import Path
import pytest
from tempfile import TemporaryDirectory
from typing import Callable

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, UnverifiablePackage
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
import scfw.verifiers.dd_verifier.dataset as dataset

from .. import utils


@pytest.mark.parametrize(
    "ecosystem,kind,package_builder,unverifiable",
    [
        (ECOSYSTEM.Npm, "malicious_intent", utils.build_registry_package, False),
        (ECOSYSTEM.Npm, "compromised_lib", utils.build_registry_package, False),
        (ECOSYSTEM.PyPI, "malicious_intent", utils.build_registry_package, False),
        (ECOSYSTEM.PyPI, "compromised_lib", utils.build_registry_package, False),
        (ECOSYSTEM.Npm, "malicious_intent", utils.build_remote_non_registry_package, True),
        (ECOSYSTEM.Npm, "compromised_lib", utils.build_remote_non_registry_package, True),
        (ECOSYSTEM.PyPI, "malicious_intent", utils.build_remote_non_registry_package, True),
        (ECOSYSTEM.PyPI, "compromised_lib", utils.build_remote_non_registry_package, True),
        (ECOSYSTEM.Npm, "malicious_intent", utils.build_local_package, True),
        (ECOSYSTEM.Npm, "compromised_lib", utils.build_local_package, True),
        (ECOSYSTEM.PyPI, "malicious_intent", utils.build_local_package, True),
        (ECOSYSTEM.PyPI, "compromised_lib", utils.build_local_package, True),
        (ECOSYSTEM.Npm, "malicious_intent", Package, False),
        (ECOSYSTEM.Npm, "compromised_lib", Package, False),
        (ECOSYSTEM.PyPI, "malicious_intent", Package, False),
        (ECOSYSTEM.PyPI, "compromised_lib", Package, False),
    ]
)
def test_dd_verifier_malicious(
    ecosystem: ECOSYSTEM,
    kind: str,
    package_builder: Callable[[ECOSYSTEM, str, str], Package],
    unverifiable: bool,
):
    """
    Run a test of the `DatadogMaliciousPackagesVerifier` against all samples
    of the given ecosystem and kind.
    """
    dd_verifier = DatadogMaliciousPackagesVerifier()

    test_set = []
    for name, versions in dd_verifier._manifests[ecosystem].items():
        if kind == "malicious_intent" and not versions:
            # Version is not checked in this case, so use a dummy version string
            test_set.append(package_builder(ecosystem, name, "dummy_version"))
        elif kind == "compromised_lib" and versions:
            test_set.extend(
                [package_builder(ecosystem, name, version) for version in versions]
            )
    assert test_set

    if unverifiable:
        for package in test_set:
            with pytest.raises(UnverifiablePackage):
                _ = dd_verifier.verify(package)
        return

    for package in test_set:
        findings = dd_verifier.verify(package)
        assert len(findings) == 1

        finding = findings.pop()
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.finding


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_update_manifest_no_change(ecosystem: ECOSYSTEM):
    """
    Test that no update occurs when we attempt to update the manifest file using
    the current ETag.
    """
    last_etag, _ = dataset._download_manifest_etagged(ecosystem)
    assert last_etag is not None

    latest_etag, latest_manifest = dataset._update_manifest(ecosystem, last_etag)

    assert latest_etag is not None and latest_etag == last_etag
    assert latest_manifest is None


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_update_manifest_change(ecosystem: ECOSYSTEM):
    """
    Tests that an update occurs with the latest ETag and manifest when we perform
    a manifest update operation using an outdated ETag value.
    """
    last_etag, last_manifest = dataset._download_manifest_etagged(ecosystem)
    latest_etag, latest_manifest = dataset._update_manifest(ecosystem, "foo")

    assert latest_etag is not None and latest_etag == last_etag
    assert latest_manifest is not None and latest_manifest == last_manifest


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_get_latest_manifest_no_cache(ecosystem: ECOSYSTEM):
    """
    Test that dataset caching occurs when caching is enabled but the directories
    or cache files do not yet exist.
    """
    with TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        latest_etag, latest_manifest = dataset._download_manifest_etagged(ecosystem)

        assert len(glob.glob(str(cache_dir / f"{ecosystem}*.json"))) == 0

        test_manifest = dataset.get_latest_manifest(cache_dir, ecosystem)

        assert test_manifest == latest_manifest
        assert len(glob.glob(str(cache_dir / f"{ecosystem}{latest_etag}.json"))) == 1


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_get_latest_manifest_cache_no_update(ecosystem: ECOSYSTEM):
    """
    Tests that no change in the cache filename or contents occurs when the cached
    manifest file is already up to date with the remote copy.
    """
    with TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)

        latest_etag, latest_manifest = dataset._download_manifest_etagged(ecosystem)
        with open(cache_dir / f"{ecosystem}{latest_etag}.json", 'w') as f:
            json.dump(latest_manifest, f)
        assert len(glob.glob(str(cache_dir / f"{ecosystem}{latest_etag}.json"))) == 1

        test_manifest = dataset.get_latest_manifest(cache_dir, ecosystem)

        assert len(glob.glob(str(cache_dir / f"{ecosystem}{latest_etag}.json"))) == 1
        with open(cache_dir / f"{ecosystem}{latest_etag}.json") as f:
            assert json.load(f) == test_manifest


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_get_latest_manifest_cache_update_invalid_etag(ecosystem: ECOSYSTEM):
    """
    Tests the cached manifest file is updated when the ETag portion of the
    file name is invalid (including outdated) with respect to the current one.
    """
    with TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)

        with open(cache_dir / f"{ecosystem}foo.json", 'w') as f:
            json.dump({}, f)
        assert len(glob.glob(str(cache_dir / f"{ecosystem}*.json"))) == 1

        dataset.get_latest_manifest(cache_dir, ecosystem)

        assert len(glob.glob(str(cache_dir / f"{ecosystem}*.json"))) == 1
        assert len(glob.glob(str(cache_dir / f"{ecosystem}foo.json"))) == 0


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_get_latest_manifest_cache_update_no_etag(ecosystem: ECOSYSTEM):
    """
     Tests the cached manifest file is updated when the file name is missing
     the ETag portion, showing that the caching logic is capable of tolerating
     and indeed repairing a missing ETag.
    """
    with TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)

        with open(cache_dir / f"{ecosystem}.json", 'w') as f:
            json.dump({}, f)
        assert len(glob.glob(str(cache_dir / f"{ecosystem}*.json"))) == 1

        dataset.get_latest_manifest(cache_dir, ecosystem)

        assert len(glob.glob(str(cache_dir / f"{ecosystem}*.json"))) == 1
        assert len(glob.glob(str(cache_dir / f"{ecosystem}.json"))) == 0
