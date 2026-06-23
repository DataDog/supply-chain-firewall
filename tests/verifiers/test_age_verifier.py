"""
Tests of `PackageAgeVerifier`.
"""

from datetime import timedelta

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, UnverifiablePackage
from scfw.verifiers.age_verifier import PackageAgeVerifier

from .. import utils

NPM_TEST_PACKAGE = ("axios", "1.14.0")
PYPI_TEST_PACKAGE = ("requests", "2.32.2")

TEST_CASES = [
    (utils.build_registry_package(ECOSYSTEM.Npm, NPM_TEST_PACKAGE[0], NPM_TEST_PACKAGE[1]), False),
    (utils.build_registry_package(ECOSYSTEM.PyPI, PYPI_TEST_PACKAGE[0], PYPI_TEST_PACKAGE[1]), False),
    (utils.build_remote_non_registry_package(ECOSYSTEM.Npm, NPM_TEST_PACKAGE[0], NPM_TEST_PACKAGE[1]), True),
    (utils.build_remote_non_registry_package(ECOSYSTEM.PyPI, PYPI_TEST_PACKAGE[0], PYPI_TEST_PACKAGE[1]), True),
    (utils.build_local_package(ECOSYSTEM.Npm, NPM_TEST_PACKAGE[0], NPM_TEST_PACKAGE[1]), True),
    (utils.build_local_package(ECOSYSTEM.PyPI, PYPI_TEST_PACKAGE[0], PYPI_TEST_PACKAGE[1]), True),
    (Package(ECOSYSTEM.Npm, NPM_TEST_PACKAGE[0], NPM_TEST_PACKAGE[1], source=None), False),
    (Package(ECOSYSTEM.PyPI, PYPI_TEST_PACKAGE[0], PYPI_TEST_PACKAGE[1], source=None), False),
]


@pytest.mark.parametrize("test_package,unverifiable", TEST_CASES)
def test_warn_on_recent_package(test_package: Package, unverifiable: bool):
    """
    Test that `PackageAgeVerifier` has findings for a package that does not have
    the required minimum age.
    """
    # Verifier with tolerance of 1M years (should work for awhile)
    recency_verifier = PackageAgeVerifier()
    recency_verifier.minimum_age = timedelta(days=365*1000000)

    if unverifiable:
        with pytest.raises(UnverifiablePackage):
            recency_verifier.verify(test_package)
        return

    results = recency_verifier.verify(test_package)
    assert len(results) == 1
    assert results.pop().severity == FindingSeverity.WARNING



@pytest.mark.parametrize("test_package,unverifiable", TEST_CASES)
def test_no_warn_on_non_recent_package(test_package: Package, unverifiable: bool):
    """
    Test that `PackageAgeVerifier` does not have findings for a package that has
    the required minimum age.
    """
    recency_verifier = PackageAgeVerifier()

    if unverifiable:
        with pytest.raises(UnverifiablePackage):
            recency_verifier.verify(test_package)
        return

    assert not recency_verifier.verify(test_package)
