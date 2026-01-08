"""
Tests of `PackageAgeVerifier`.
"""

from datetime import timedelta

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity
from scfw.verifiers.age_verifier import PackageAgeVerifier

# Version numbers are irrelevant for this verifier, so we use dummy values
TEST_PACKAGES = [
    Package(ECOSYSTEM.Npm, "axios", "foo"),
    Package(ECOSYSTEM.PyPI, "requests", "foo"),
]


@pytest.mark.parametrize("test_package", TEST_PACKAGES)
def test_warn_on_recent_package(test_package: Package):
    """
    Test that `PackageAgeVerifier` has findings for a package that does not have
    the required minimum age.
    """
    # Verifier with tolerance of 1M years (should work for awhile)
    recency_verifier = PackageAgeVerifier()
    recency_verifier.minimum_age = timedelta(days=365*1000000)

    results = recency_verifier.verify(test_package)
    assert len(results) == 1
    assert results[0][0] == FindingSeverity.WARNING



@pytest.mark.parametrize("test_package", TEST_PACKAGES)
def test_no_warn_on_non_recent_package(test_package: Package):
    """
    Test that `PackageAgeVerifier` does not have findings for a package that has
    the required minimum age.
    """
    recency_verifier = PackageAgeVerifier()

    assert not recency_verifier.verify(test_package)
