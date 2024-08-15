import itertools
import sys

from ecosystem import ECOSYSTEM
from firewall import verify_install_targets
from resolvers.npm_resolver import NpmInstallTargetsResolver
from resolvers.pip_resolver import PipInstallTargetsResolver
from verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
from verifiers.osv_verifier import OsvVerifier


def main() -> int:
    try:
        # TODO: Add a real CLI
        if len(sys.argv) < 2:
            return 0
    
        match sys.argv[1]:
            case ECOSYSTEM.PIP.value:
                targets = PipInstallTargetsResolver().resolve_targets(sys.argv[1:])
            case ECOSYSTEM.NPM.value:
                targets = NpmInstallTargetsResolver().resolve_targets(sys.argv[1:])
            case _:
                raise Exception(f"Unsupported ecosystem '{sys.argv[1]}'")
    
        # TODO: Automatically discover verifiers in the verifiers directory
        verifiers = [DatadogMaliciousPackagesVerifier(), OsvVerifier()]

        findings = verify_install_targets(targets, verifiers)
        if findings:
            # TODO: Structure this output better
            print("Installation blocked")
            for target, target_findings in findings.items():
                print(f"Installation target {target.show()}:")
                for finding in target_findings:
                    print(f"  - {finding}")
        else:
            print("No security advisories found for installation targets")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
