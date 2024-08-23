from scfw.ecosystem import ECOSYSTEM
from scfw.firewall import verify_install_targets
from scfw.target import InstallTarget
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier

# Create a single Datadog malicious packages verifier to use for testing
DD_VERIFIER = DatadogMaliciousPackagesVerifier()


def test_dd_verifier_malicious_pypi():
    """
    Test that every Python package in the Datadog malicious packages dataset
    has a `DatadogMaliciousPackagesVerifier` finding (and therefore would block)
    """
    _test_dd_verifier_backend(ECOSYSTEM.PIP)


def test_dd_verifier_malicious_npm():
    """
    Test that every npm package in the Datadog malicious packages dataset
    has a `DatadogMaliciousPackagesVerifier` finding (and therefore would block)
    """
    _test_dd_verifier_backend(ECOSYSTEM.NPM)


def _test_dd_verifier_backend(ecosystem: ECOSYSTEM):
    """
    Backend function for implementing the tests in this module.
    """
    match ecosystem:
        case ECOSYSTEM.PIP:
            manifest = DD_VERIFIER.pypi_manifest
        case ECOSYSTEM.NPM:
            manifest = DD_VERIFIER.npm_manifest

    # Only the package name is checked, so use a dummy version string
    test_set = [
        InstallTarget(ecosystem, package, "dummy version") for package in manifest
    ]
    findings = verify_install_targets([DD_VERIFIER], test_set)
    assert findings
    for target in test_set:
        assert target in findings
        assert findings[target]
