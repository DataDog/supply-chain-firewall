"""
Provides the core orchestration logic for verifying a set of installation targets
and structuring and printing the results.
"""

import concurrent.futures as cf
import itertools
import logging
from typing import Iterator, Optional

from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

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

    def targets(self) -> Iterator[InstallTarget]:
        """
        Return an iterator over the reported installation targets.

        Returns:
            A generator object that iterates over the reported `InstallTarget`s.
        """
        yield from self._report

    def has_findings(self) -> bool:
        """
        Determine whether any installation target mentioned in the report has findings.

        Returns:
            A `bool` indicating whether any `InstallTarget` mentioned in the report has findings.
        """
        return any(findings != [] for _, findings in self._report.items())

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

    def show(self) -> str:
        """
        Return a human-readable version of the verification report suitable for printing
        and displaying to the user.

        Returns:
            A `str` containing the formatted verification report.
        """
        def format_line(linenum: int, line: str) -> str:
            if linenum == 0:
                return f"  - {line}"
            else:
                return f"    {line}"

        def print_finding(finding: str) -> str:
            return '\n'.join(
                format_line(linenum, line) for linenum, line in enumerate(finding.split('\n'))
            )

        def print_findings(target: InstallTarget, findings: list[str]) -> str:
            return (
                f"Installation target {target.show()}:\n" + '\n'.join(map(print_finding, findings))
            )

        return '\n'.join(
            print_findings(target, findings) for target, findings in self._report.items()
        )


def verify_install_targets(
    verifiers: list[InstallTargetVerifier],
    targets: list[InstallTarget]
) -> VerificationReport:
    """
    Verify a set of installation targets against a set of verifiers.

    Args:
        verifiers: The set of verifiers to use against the installation targets.
        targers: A list of installation targets to be verified.

    Returns:
        A `VerificationReport` containing the findings that resulted from verifying `targets`
        against `verifiers`.

        The returned report is such that only the installation targets that had at least one
        finding are present.  There were no findings for any member of `targets` not mentioned
        in the report.
    """
    report = VerificationReport()

    with cf.ThreadPoolExecutor() as executor:
        task_results = {
            executor.submit(lambda v, t: v.verify(t), verifier, target): (verifier.name(), target)
            for verifier, target in itertools.product(verifiers, targets)
        }
        for future in cf.as_completed(task_results):
            verifier, target = task_results[future]
            if (finding := future.result()):
                _log.info(f"{verifier} had findings for target {target.show()}")
                report.add_finding(target, finding)
            else:
                _log.info(f"{verifier} had no findings for target {target.show()}")

    _log.info(
        f"Verification complete: {sum(1 for _ in report.targets())} of {len(targets)} targets had findings"
    )
    return report
