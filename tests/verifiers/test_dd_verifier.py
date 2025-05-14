"""
Tests of `DatadogMaliciousPackagesVerifier.
"""

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity
from scfw.verifiers import FirewallVerifiers
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier

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

    reports = verifier.verify_targets(test_set)
    assert (critical_report := reports.get(FindingSeverity.CRITICAL))
    assert not reports.get(FindingSeverity.WARNING)

    for target in test_set:
        assert critical_report.get(target)
