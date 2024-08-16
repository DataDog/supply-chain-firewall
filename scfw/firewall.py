import itertools
import multiprocessing as mp
import subprocess
import sys

from scfw.resolvers import get_install_targets_resolver
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
from scfw.verifiers import get_install_target_verifiers


def _perform_verify_task(target: InstallTarget, verifier: InstallTargetVerifier, findings: dict[InstallTarget, list[str]]):
    if (finding := verifier.verify(target)):
        if target not in findings:
            findings[target] = [finding]
        else:
            findings[target].append(finding)


def verify_install_targets(targets: list[InstallTarget], verifiers: list[InstallTargetVerifier]) -> dict[InstallTarget, list[str]]:
    manager = mp.Manager()
    findings = manager.dict()

    verify_tasks = itertools.product(targets, verifiers)

    with manager.Pool() as pool:
        pool.starmap(
            _perform_verify_task,
            [(target, verifier, findings) for target, verifier in verify_tasks]
        )

    return findings


def run_firewall() -> int:
    try:
        # TODO: Add a real CLI
        if len(sys.argv) < 2:
            return 0

        resolver = get_install_targets_resolver(sys.argv[1])
        targets = resolver.resolve_targets(sys.argv[1:])
        verifiers = get_install_target_verifiers()

        findings = verify_install_targets(targets, verifiers)
        if findings:
            # TODO: Structure this output better
            for target, target_findings in findings.items():
                print(f"Installation target {target.show()}:")
                for finding in target_findings:
                    print(f"  - {finding}")
            print("\nThe installation request was blocked.  No changes have been made.")
        else:
            subprocess.run(sys.argv[1:])

        return 0
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
