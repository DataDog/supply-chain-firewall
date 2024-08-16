from scfw.verifier import InstallTargetVerifier
from scfw.verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
from scfw.verifiers.osv_verifier import OsvVerifier


# TODO: Automatically discover verifiers in this directory
def get_install_target_verifiers() -> list[InstallTargetVerifier]:
    return [
        DatadogMaliciousPackagesVerifier(),
        OsvVerifier()
    ]
