import sys

from ecosystem import ECOSYSTEM
from resolvers.pip_resolver import PipInstallTargetsResolver
from verifiers.osv_verifier import OsvVerifier

try:
    # TODO: Add a real CLI
    if len(sys.argv) < 2:
        sys.exit(0)
    
    match sys.argv[1]:
        case ECOSYSTEM.PIP.value:
            install_targets = PipInstallTargetsResolver().resolve_targets(sys.argv[1:])
        case ECOSYSTEM.NPM.value:
            sys.stderr.write("npm not yet supported\n")
        case _:
            raise Exception(f"Unsupported ecosystem '{sys.argv[1]}'")
    
    install = True
    osv_verifier = OsvVerifier()

    # TODO: Parallelize over targets and verifiers
    while install and install_targets:
        target = install_targets.pop()
        if (osv_id := osv_verifier.verify(target)):
            print(f"Installation blocked: target '{target.show()}' is vulnerable or malicious (OSV ID: {osv_id})")
            install = False
    
    if install:
        print("All installation targets verified, proceeding...")
        print(f"Running command \"{' '.join(sys.argv[1:])}\" (not really)")

    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
