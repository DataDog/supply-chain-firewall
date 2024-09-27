"""
Provides the core orchestration logic for verifying a set of installation targets
and structuring and printing the results.
"""

import concurrent.futures as cf
import itertools
import logging
from typing import TypeAlias

from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity, InstallTargetVerifier

_log = logging.getLogger(__name__)


VerificationReport: TypeAlias = dict[InstallTarget, list[str]]
"""A structured report containing findings resulting from installation target verification."""


def verify_install_targets(
    verifiers: list[InstallTargetVerifier],
    targets: list[InstallTarget]
) -> dict[FindingSeverity, VerificationReport]:
    """
    Verify a set of installation targets against a set of verifiers.

    Args:
        verifiers: The set of verifiers to use against the installation targets.
        targers: A list of installation targets to be verified.

    Returns:
        A `dict[FindingSeverity, VerificationReport]` representing the severity-ranked
        results of verification across all installation targets and verifiers.

        The returned `dict` is such that a given `FindingSeverity` key is present iff
        its `VerificationReport` value has a finding for some installation target.
        Moreover, this finding was determined to be at that severity level by the
        verifier that returned it.
    """
    reports: dict[FindingSeverity, VerificationReport] = {}

    with cf.ThreadPoolExecutor() as executor:
        task_results = {
            executor.submit(lambda v, t: v.verify(t), verifier, target): (verifier.name(), target)
            for verifier, target in itertools.product(verifiers, targets)
        }
        for future in cf.as_completed(task_results):
            verifier, target = task_results[future]
            if (findings := future.result()):
                _log.info(f"Verifier {verifier} had findings for target {target}")
                for severity, finding in findings:
                    if severity not in reports:
                        reports[severity] = {}
                    if target not in reports[severity]:
                        reports[severity][target] = [finding]
                    else:
                        reports[severity][target].append(finding)
            else:
                _log.info(f"Verifier {verifier} had no findings for target {target}")

    _log.info("Verification of installation targets complete")
    return reports


def show_verification_report(report: VerificationReport) -> str:
    """
    Return a human-readable version of a verification report.

    Returns:
        A `str` containing the formatted verification report.
    """
    def show_line(linenum: int, line: str) -> str:
        return (f"  - {line}" if linenum == 0 else f"    {line}")

    def show_finding(finding: str) -> str:
        return '\n'.join(
            show_line(linenum, line) for linenum, line in enumerate(finding.split('\n'))
        )

    def show_findings(target: InstallTarget, findings: list[str]) -> str:
        return (
            f"Installation target {target}:\n" + '\n'.join(map(show_finding, findings))
        )

    return '\n'.join(
        show_findings(target, findings) for target, findings in report.items()
    )
