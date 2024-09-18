"""
Provides the core orchestration logic for verifying a set of installation targets
and structuring and printing the results.
"""

import concurrent.futures as cf
import itertools
import logging
from typing import Iterator, Optional

from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity, InstallTargetVerifier

_log = logging.getLogger(__name__)


class VerificationReport:
    """
    A structured report containing the findings that resulted from verifying a set of
    installation targets.
    """
    def __init__(self):
        """
        Initialize a new, empty verification report.
        """
        self._report = {}

    def __contains__(self, target: InstallTarget) -> bool:
        return target in self._report

    def __str__(self) -> str:
        """
-        Return a human-readable version of the verification report suitable for printing
-        and displaying to the user.
-
-        Returns:
-            A `str` containing the formatted verification report.
-        """
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
            show_findings(target, findings) for target, findings in self._report.items()
        )

    def install_targets(self) -> Iterator[InstallTarget]:
        """
        Return an iterator over the reported installation targets.

        Returns:
            A generator object that iterates over the reported `InstallTarget`s.
        """
        yield from self._report

    def findings(self) -> Iterator[tuple[InstallTarget, list[str]]]:
        """
        Return an iterator over the pairs of installation targets and findings
        contained in the report.

        Returns:
            A generator object that iterates over the reports contents.
        """
        yield from self._report.items()

    def get_findings(self, target: InstallTarget) -> Optional[list[str]]:
        """
        Return the findings, if any, for a given installation target.

        Args:
            target: The installation target whose findings are desired.

        Returns:
            The reported findings (as a `list[str]`) for the given target or `None` if
            the target was not reported.
        """
        return self._report.get(target)

    def add_finding(self, target: InstallTarget, finding: str):
        """
        Add a finding to the verification report.

        Args:
            target: The installation target the finding pertains to.
            finding: The finding to be added to the report.
        """
        if target not in self._report:
            self._report[target] = [finding]
        else:
            self._report[target].append(finding)


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
    reports = {}

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
                        reports[severity] = VerificationReport()
                    reports[severity].add_finding(target, finding)
            else:
                _log.info(f"Verifier {verifier} had no findings for target {target}")

    _log.info("Verification of installation targets complete")
    return reports
