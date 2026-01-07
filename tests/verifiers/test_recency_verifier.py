"""
Tests of `PackageRecencyVerifier`.
"""

from datetime import timedelta

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity
from scfw.verifiers.recency_verifier import PackageRecencyVerifier

# Version numbers are irrelevant for this verifier, so we use dummy values
TEST_PACKAGES = [
    Package(ECOSYSTEM.Npm, "axios", "foo"),
    Package(ECOSYSTEM.PyPI, "requests", "foo"),
]


@pytest.mark.parametrize("test_package", TEST_PACKAGES)
def test_warn_on_recent_package(test_package: Package):
    """
    Test that `PackageRecencyVerifier` has findings for a package that was created
    outside of its configured recency tolerance.
    """
    # Verifier with tolerance of 1M years (should work for awhile)
    recency_verifier = PackageRecencyVerifier()
    recency_verifier.tolerance = timedelta(days=365*1000000)

    results = recency_verifier.verify(test_package)
    assert len(results) == 1
    assert results[0][0] == FindingSeverity.WARNING



@pytest.mark.parametrize("test_package", TEST_PACKAGES)
def test_no_warn_on_non_recent_package(test_package: Package):
    """
    Test that `PackageRecencyVerifier` does not have findings for a package that was
    created within its configured recency tolerance.
    """
    recency_verifier = PackageRecencyVerifier()

    assert not recency_verifier.verify(test_package)
