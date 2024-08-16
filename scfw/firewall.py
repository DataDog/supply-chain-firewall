import itertools
import multiprocessing as mp

from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier


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
