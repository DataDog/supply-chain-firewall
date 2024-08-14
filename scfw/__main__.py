import itertools
import sys

from ecosystem import ECOSYSTEM
from resolvers.npm_resolver import NpmInstallTargetsResolver
from resolvers.pip_resolver import PipInstallTargetsResolver
from verifiers.dd_verifier import DatadogMaliciousPackagesVerifier
from verifiers.osv_verifier import OsvVerifier

try:
    # TODO: Add a real CLI
    if len(sys.argv) < 2:
        sys.exit(0)
    
    match sys.argv[1]:
        case ECOSYSTEM.PIP.value:
            install_targets = PipInstallTargetsResolver().resolve_targets(sys.argv[1:])
        case ECOSYSTEM.NPM.value:
            install_targets = NpmInstallTargetsResolver().resolve_targets(sys.argv[1:])
        case _:
            raise Exception(f"Unsupported ecosystem '{sys.argv[1]}'")
    
    # TODO: Automatically discover verifiers in the verifiers directory
    verifiers = [DatadogMaliciousPackagesVerifier(), OsvVerifier()]

    findings = {}
    # TODO: Parallelize over this set of jobs
    for target, verifier in itertools.product(install_targets, verifiers):
        if (finding := verifier.verify(target)):
            if target not in findings:
                findings[target] = [finding]
            else:
                findings[target].append(finding)
    
    if findings:
        # TODO: Structure this output better
        print("Installation blocked")
        for target, target_findings in findings.items():
            print(f"Installation target {target.show()}:")
            for finding in target_findings:
                print(f"  - {finding}")
    else:
        print("No security advisories found for installation targets")

    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
