"""
Exports the current set of installation target verifiers for use in the
supply-chain firewall's main routine.
"""

from scfw.verifier import InstallTargetVerifier
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
from scfw.verifiers.osv_verifier import OsvVerifier


def get_install_target_verifiers() -> list[InstallTargetVerifier]:
    """
    Return the current set of installation target verifiers.

    Returns:
        A list of initialized installation target verifiers, one per currently
        available type.
    """
    return [
        DatadogMaliciousPackagesVerifier(),
        OsvVerifier()
    ]
