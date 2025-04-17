import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
from scfw.verify import verify_install_targets

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
    test_set = [
        InstallTarget(ecosystem, package, "dummy version") for package in manifest
    ]

    reports = verify_install_targets([DD_VERIFIER], test_set)
    assert (critical_report := reports.get(FindingSeverity.CRITICAL))
    assert not reports.get(FindingSeverity.WARNING)

    for target in test_set:
        assert critical_report.get(target)
