"""
Provides the core orchestration logic for verifying a set of installation targets
and structuring and printing the results.
"""

import concurrent.futures as cf
import itertools
import logging

from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

_log = logging.getLogger(__name__)


def verify_install_targets(
    verifiers: list[InstallTargetVerifier],
    targets: list[InstallTarget]
) -> dict[InstallTarget, list[str]]:
    """
    Verify a set of installation targets against a set of verifiers.

    Args:
        verifiers: The set of verifiers to use against the installation targets.
        targers: A list of installation targets to be verified.

    Returns:
        A `dict` associating installation targets with its verification findings.

        If a given target is not present as a key in the returned `dict`, there
        were no findings for it. An empty returned `dict` indicates that no target
        had findings, i.e., that the installation can proceed.
    """
    findings = {}

    with cf.ThreadPoolExecutor() as executor:
        task_results = {
            executor.submit(lambda v, t: v.verify(t), verifier, target): (verifier.name(), target)
            for verifier, target in itertools.product(verifiers, targets)
        }
        for future in cf.as_completed(task_results):
            verifier, target = task_results[future]
            if (finding := future.result()):
                _log.info(f"{verifier} had findings for target {target.show()}")
                if target not in findings:
                    findings[target] = [finding]
                else:
                    findings[target].append(finding)
            else:
                _log.info(f"{verifier} had no findings for target {target.show()}")

    _log.info(
        f"Verification complete: {len(findings)} of {len(targets)} installation targets had findings"
    )
    return findings


def print_findings(findings: dict[InstallTarget, list[str]]):
    """
    Print the findings accrued for targets during verification.

    Args:
        findings:
            The `dict` of findings for the verified installation targets returned
            by `verify_install_targets()`.
    """
    def print_finding(finding: str):
        for linenum, line in enumerate(finding.split('\n')):
            if linenum == 0:
                print(f"  - {line}")
            else:
                print(f"    {line}")

    for target, target_findings in findings.items():
        print(f"Installation target {target.show()}:")
        for finding in target_findings:
            print_finding(finding)
