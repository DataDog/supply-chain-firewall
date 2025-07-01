"""
Tests of `DatadogMaliciousPackagesVerifier`.
"""

import glob
import json
from pathlib import Path
import pytest
from tempfile import TemporaryDirectory

from scfw.configure import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity
from scfw.verifiers import FirewallVerifiers
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
import scfw.verifiers.dd_verifier.dataset as dataset

# Create a single Datadog malicious packages verifier to use for testing
DD_VERIFIER = DatadogMaliciousPackagesVerifier()


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_dd_verifier_malicious(ecosystem: ECOSYSTEM):
    """
    Run a test of the `DatadogMaliciousPackagesVerifier` against all samples
    present for the given ecosystem.
    """
    match ecosystem:
        case ECOSYSTEM.Npm:
            manifest = DD_VERIFIER._npm_manifest
        case ECOSYSTEM.PyPI:
            manifest = DD_VERIFIER._pypi_manifest

    # Only the package name is checked, so use a dummy version string
    test_set = [Package(ecosystem, name, "dummy version") for name in manifest]

    # Create a modified `FirewallVerifiers` only containing the Datadog verifier
    verifier = FirewallVerifiers()
    verifier._verifiers = [DD_VERIFIER]

    reports = verifier.verify_packages(test_set)
    assert (critical_report := reports.get(FindingSeverity.CRITICAL))
    assert not reports.get(FindingSeverity.WARNING)

    for package in test_set:
        assert critical_report.get(package)


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_update_manifest_no_change(ecosystem: ECOSYSTEM):
    """
    Test that no update occurs when we attempt to update the manifest file using
    the current ETag.
    """
    last_etag, _ = dataset.download_manifest(ecosystem)
    latest_etag, latest_manifest = dataset._update_manifest(ecosystem, last_etag)

    assert latest_etag is not None and latest_etag == last_etag
    assert latest_manifest is None


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_update_manifest_change(ecosystem: ECOSYSTEM):
    """
    Tests that an update occurs with the latest ETag and manifest when we perform
    a manifest update operation using an outdated ETag value.
    """
    last_etag, last_manifest = dataset.download_manifest(ecosystem)
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
        latest_etag, latest_manifest = dataset.download_manifest(ecosystem)

        assert len(glob.glob(str(cache_dir / f"{ecosystem}*.json"))) == 0

        test_manifest = dataset.get_latest_manifest(cache_dir, ecosystem)

        assert  test_manifest == latest_manifest
        assert len(glob.glob(str(cache_dir / f"{ecosystem}{latest_etag}.json"))) == 1


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_get_latest_manifest_cache_no_update(ecosystem: ECOSYSTEM):
    """
    Tests that no change in the cache filename or contents occurs when the cached
    manifest file is already up to date with the remote copy.
    """
    with TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)

        latest_etag, latest_manifest = dataset.download_manifest(ecosystem)
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
