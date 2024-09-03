import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.firewall import verify_install_targets
from scfw.target import InstallTarget
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier

# Create a single Datadog malicious packages verifier to use for testing
DD_VERIFIER = DatadogMaliciousPackagesVerifier()


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.PIP, ECOSYSTEM.NPM])
def test_dd_verifier_malicious(ecosystem: ECOSYSTEM):
    """
    Run a test of the `DatadogMaliciousPackagesVerifier` against all samples
    present for the given ecosystem.
    """
    match ecosystem:
        case ECOSYSTEM.PIP:
            manifest = DD_VERIFIER._pypi_manifest
        case ECOSYSTEM.NPM:
            manifest = DD_VERIFIER._npm_manifest

    # Only the package name is checked, so use a dummy version string
    test_set = [
        InstallTarget(ecosystem, package, "dummy version") for package in manifest
    ]
    findings = verify_install_targets([DD_VERIFIER], test_set)
    for target in test_set:
        assert target in findings
        assert findings[target]
